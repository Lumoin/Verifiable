using System.Diagnostics;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.JCose;

namespace Verifiable.Vcalm;

/// <summary>
/// Endpoint builder for the W3C VCALM 1.0 issuer service
/// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
/// Management</see>) — the §3.2.1 <c>POST /credentials/issue</c> interface a §1.3 conforming issuer
/// MUST provide, plus the MAY §3.2.2 <c>GET /credentials/{id}</c> and §3.2.3
/// <c>DELETE /credentials/{id}</c> interfaces. Register at startup via
/// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
/// </summary>
/// <remarks>
/// <para>
/// Each endpoint is stateless (<see cref="StatelessFlowKind"/>): a single request reads the body,
/// parses it through the application's parse seam (the serialization firewall keeps STJ behind the
/// seam), composes the library's tested Data Integrity signer through
/// <see cref="VcalmCredentialIssuanceService"/>, and writes the §3.2 response with
/// <see cref="VcalmResponseWriter"/>. There is no flow state and no PDA.
/// </para>
/// <para>
/// §2.4 boundary MUSTs are enforced for the §3.2.1 body exactly as the verifier enforces them: the
/// body MUST be <c>application/json</c> (else 400), MUST be within
/// <see cref="VcalmIntegration.VcalmMaxRequestBytes"/> (else 413), and MUST NOT carry an option /
/// member the issuer does not understand (an unknown option → 400 with the §3.8
/// <see cref="VcalmProblemTypes.UnknownOptionProvided"/> type).
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmIssuerEndpoints")]
public static class VcalmIssuerEndpoints
{
    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        EndpointServer? server = context.Server;
        if(registration.AllowedCapabilities.Contains(WellKnownVcalmCapabilities.VcalmIssuer))
        {
            //§3.2.1 is the §1.3 REQUIRED issuer interface; it materializes only when the parse seam
            //and the signing configuration are both wired (fail-closed — an issuer that cannot read
            //its body or cannot secure a credential would be a dead route).
            if(server?.Vcalm().ParseVcalmIssueCredentialAsync is not null
                && server?.Vcalm().VcalmCredentialIssuance is not null)
            {
                candidates.Add(BuildCredentialsIssue());
            }

            //§3.2.2 / §3.2.3 are MAYs that need the matching storage seam — the library never owns
            //the issued-credential store, so an instance with no store does not advertise retrieval
            //or deletion.
            if(server?.Vcalm().LoadVcalmIssuedCredentialAsync is not null)
            {
                candidates.Add(BuildGetCredential());
            }

            if(server?.Vcalm().DeleteVcalmIssuedCredentialAsync is not null)
            {
                candidates.Add(BuildDeleteCredential());
            }
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(candidates);
    };


    //§3.2.1 POST /credentials/issue.
    private static EndpointCandidate BuildCredentialsIssue() =>
        new()
        {
            Name = WellKnownVcalmEndpointNames.VcalmCredentialsIssue,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownVcalmCapabilities.VcalmIssuer,
            StartsNewFlow = true,
            Kind = StatelessFlowKind.Instance,

            MatchesRequest = static (fields, context, endpoint, ct) => MatchExact(context, endpoint, WellKnownHttpMethods.Post),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var oauth = server.Vcalm();

                ServerHttpResponse? boundaryFailure = CheckRequestBoundary(context, server, out string requestBody);
                if(boundaryFailure is not null)
                {
                    return (null, boundaryFailure);
                }

                VcalmIssueCredentialRequest? request = await oauth.ParseVcalmIssueCredentialAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(request is null || request.Failure == VcalmParseFailure.Malformed)
                {
                    return (null, MalformedRequest());
                }

                //§2.4 unknown-option is checked before the credential-presence check: an unknown
                //option short-circuits the parser before it materializes the credential, and the §2.4
                //MUST is the more specific outcome.
                if(request.Failure == VcalmParseFailure.UnknownOption)
                {
                    return (null, UnknownOptionRequest());
                }

                if(request.Credential is null)
                {
                    return (null, MalformedRequest());
                }

                return (null, await IssueAsync(server, request, context, ct).ConfigureAwait(false));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    //§3.2.2 GET /credentials/{id}.
    private static EndpointCandidate BuildGetCredential() =>
        new()
        {
            Name = WellKnownVcalmEndpointNames.VcalmGetCredential,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownVcalmCapabilities.VcalmIssuer,
            StartsNewFlow = true,
            Kind = StatelessFlowKind.Instance,

            MatchesRequest = static (fields, context, endpoint, ct) =>
                MatchCredentialIdPath(context, endpoint, WellKnownHttpMethods.Get),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var oauth = server.Vcalm();

                string? credentialId = ExtractCredentialId(context);
                if(string.IsNullOrEmpty(credentialId))
                {
                    return (null, MalformedRequest());
                }

                VcalmStoredCredential? stored = await oauth.LoadVcalmIssuedCredentialAsync!(
                    credentialId, context, ct).ConfigureAwait(false);

                //§3.2.2: 404 when no record exists, 410 Gone for a soft-deleted (§3.2.3) tombstone,
                //200 with the secured credential otherwise. The 418 "I'm a teapot" rule is "MUST not
                //be returned outside of pre-arranged scenarios between both parties" — this library
                //never emits 418.
                if(stored is null)
                {
                    return (null, ServerHttpResponse.NotFound());
                }

                if(stored.IsDeleted)
                {
                    return (null, Gone());
                }

                string body = VcalmResponseWriter.BuildVerifiableCredentialResponse(stored.VerifiableCredentialJson);

                return (null, ServerHttpResponse.Ok(body, WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    //§3.2.3 DELETE /credentials/{id}.
    private static EndpointCandidate BuildDeleteCredential() =>
        new()
        {
            Name = WellKnownVcalmEndpointNames.VcalmDeleteCredential,
            HttpMethod = WellKnownHttpMethods.Delete,
            Capability = WellKnownVcalmCapabilities.VcalmIssuer,
            StartsNewFlow = true,
            Kind = StatelessFlowKind.Instance,

            MatchesRequest = static (fields, context, endpoint, ct) =>
                MatchCredentialIdPath(context, endpoint, WellKnownHttpMethods.Delete),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var oauth = server.Vcalm();

                string? credentialId = ExtractCredentialId(context);
                if(string.IsNullOrEmpty(credentialId))
                {
                    return (null, MalformedRequest());
                }

                bool existed = await oauth.DeleteVcalmIssuedCredentialAsync!(
                    credentialId, context, ct).ConfigureAwait(false);

                //§3.2.3: 404 when no record exists; otherwise 202 — "this is a 202 by default as soft
                //deletes and processing time are assumed". B.3 (partial vs complete deletion and any
                //status side-effects) is the application's concern behind the delete seam.
                if(!existed)
                {
                    return (null, ServerHttpResponse.NotFound());
                }

                return (null, ServerHttpResponse.Accepted());
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    //§3.2.1 issuance: validate the issuer-identity match, secure the credential, persist it under its
    //credentialId, and return the 201 IssueCredentialResponse.
    private static async ValueTask<ServerHttpResponse> IssueAsync(
        EndpointServer server,
        VcalmIssueCredentialRequest request,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        var oauth = server.Vcalm();
        VcalmCredentialIssuance issuance = oauth.VcalmCredentialIssuance!;
        VerifiableCredential credential = request.Credential!;

        //§3.2.1 / §2.4: the issuer MUST NOT sign a structurally invalid credential. A Verifiable
        //Credential requires a non-empty @context, a type that includes VerifiableCredential, an
        //issuer, and at least one credentialSubject (VC-DM §4); an absent or empty one of these is a
        //400 rather than a signed-but-invalid credential. Wrong-typed members are already refused at
        //parse; this catches the absent / empty ones that bind to default model values.
        ServerHttpResponse? structuralFailure = ValidateCredentialStructure(credential);
        if(structuralFailure is not null)
        {
            return structuralFailure;
        }

        //§3.2.1 400: "The provided value of 'issuer' does not match the expected configuration." The
        //issuer id (whether given as a string or an object) must equal the instance's configured
        //identity.
        string? requestIssuerId = credential.Issuer?.Id;
        if(!string.Equals(requestIssuerId, issuance.ConfiguredIssuer, StringComparison.Ordinal))
        {
            return IssuerMismatchRequest();
        }

        //§3.2.1 / §2.4 mandatoryPointers: an instance that does not support the option (no
        //selective-disclosure cryptosuite) rejects it as an unknown/inapplicable option. "any given
        //instance configuration MAY prohibit client use of some options properties."
        if(request.Options.HasMandatoryPointers && !issuance.SupportsMandatoryPointers)
        {
            return UnknownOptionRequest();
        }

        //§3.2.1 credentialId: auto-populated from credential.id when not provided; the issuer SHOULD
        //NOT set both. A credentialId that contradicts a present credential.id is an ambiguous
        //identity the instance cannot honour ("credentialId is a means of identifying a credential
        //without the id property being set") — a 400. Equal values are harmless; a credentialId
        //without a credential.id is the intended use.
        string? credentialIdResolution = ResolveCredentialId(request, out bool isCredentialIdConflict);
        if(isCredentialIdConflict)
        {
            return CredentialIdConflictRequest();
        }

        DateTime proofCreated = server.TimeProvider.GetUtcNow().UtcDateTime;

        //§3.8 process-safety boundary (mirrors the verifier's): the credential passed structural
        //validation, but the Data Integrity signer canonicalizes it, and an RDFC JSON-LD canonicalizer
        //THROWS on content the JSON model accepts yet JSON-LD rejects — an unresolvable @context URL, an
        //invalid @id, a non-string @context item. Such a throw is client-malformed input that MUST be a
        //sanitized §3.8.1 MALFORMED_VALUE_ERROR 400, never an unhandled 500 leaking the inner message.
        VcalmIssuanceResult result;
        try
        {
            result = await VcalmCredentialIssuanceService.IssueAsync(
                credential,
                request.HasExistingProof,
                issuance,
                proofCreated,
                context,
                cancellationToken).ConfigureAwait(false);
        }
        catch(Exception ex) when(ex is not OperationCanceledException and not OutOfMemoryException)
        {
            return MalformedCredentialRequest(
                "The credential could not be secured: it is not valid JSON-LD or could not be canonicalized.");
        }

        if(!result.IsSuccess)
        {
            //§3.2.1 Error Handling: the instance is configured to only accept credentials without
            //existing proofs and a pre-proofed credential was provided.
            return ExistingProofRejectedRequest();
        }

        string securedCredentialJson = issuance.SigningDescriptors[0].SerializeCredential(result.SecuredCredential!);

        //§3.2.2 / §3.2.3 persistence: store the secured credential under its id so the retrieval /
        //deletion interfaces can reach it. §3.2.1: when neither credentialId nor credential.id is
        //given "it will not be possible to refer to this credential once issued" — the store seam is
        //skipped, the credential is still returned.
        if(!string.IsNullOrEmpty(credentialIdResolution)
            && oauth.StoreVcalmIssuedCredentialAsync is { } store)
        {
            await store(credentialIdResolution, securedCredentialJson, context, cancellationToken).ConfigureAwait(false);
        }

        string body = VcalmResponseWriter.BuildVerifiableCredentialResponse(securedCredentialJson);

        return ServerHttpResponse.Created(body, WellKnownMediaTypes.Application.Json);
    }


    //§3.2.1 credentialId resolution: the explicit options.credentialId when present, else
    //auto-populated from credential.id. Sets isConflict when both are present and differ (the
    //ambiguous-identity case the instance cannot honour).
    private static string? ResolveCredentialId(VcalmIssueCredentialRequest request, out bool isConflict)
    {
        isConflict = false;

        string? optionId = request.Options.HasCredentialId ? request.Options.CredentialId : null;
        string? credentialId = request.CredentialId;

        if(!string.IsNullOrEmpty(optionId) && !string.IsNullOrEmpty(credentialId)
            && !string.Equals(optionId, credentialId, StringComparison.Ordinal))
        {
            isConflict = true;

            return null;
        }

        //§3.2.1: "the issuer service will auto-populate its value from credential.id" when
        //credentialId is not provided. The issuer SHOULD NOT auto-generate one when neither is given,
        //so a null result here is left null (the credential is issued, just unreferenceable).
        return !string.IsNullOrEmpty(optionId) ? optionId : credentialId;
    }


    //Reads the {id} path segment the §3.2.2 / §3.2.3 matcher extracted and carried on the match
    //payload. A skin that did template routing (/credentials/{credentialId}) populates the same id on
    //the request's RouteValues, which the matcher also honours.
    private static string? ExtractCredentialId(ExchangeContext context)
    {
        if(context.MatchPayload is VcalmCredentialIdMatchPayload payload && !string.IsNullOrEmpty(payload.CredentialId))
        {
            return Uri.UnescapeDataString(payload.CredentialId);
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


    //§3.2.2 / §3.2.3 path matcher: the given method to a path that is the issuer's resolved
    // /credentials collection path plus a single non-empty trailing {id} segment. The resolved URI is
    //the collection path; the request adds the id. The route-value extraction in ExtractCredentialId
    //reads the id the skin parsed.
    private static ValueTask<MatchPayload?> MatchCredentialIdPath(
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

        //A skin that did template routing populates the id on RouteValues; honour it first.
        if(req.RouteValues.TryGetValue(WellKnownVcalmRouteParameters.CredentialId, out string? routeValue)
            && !string.IsNullOrEmpty(routeValue))
        {
            return ValueTask.FromResult<MatchPayload?>(new VcalmCredentialIdMatchPayload(routeValue));
        }

        //Otherwise the request path must be {collection}/{id}: the collection prefix followed by a
        //slash and a single non-empty segment carrying no further slashes.
        string collectionPath = endpoint.ResolvedUri.AbsolutePath;
        if(!TryExtractTrailingSegment(req.Path, collectionPath, out string idSegment))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        return ValueTask.FromResult<MatchPayload?>(new VcalmCredentialIdMatchPayload(idSegment));
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


    //§2.4 request-boundary MUSTs for the §3.2.1 body, mirroring the verifier: a body MUST be present,
    //within the configured size cap (else 413), and application/json (else 400).
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

        if(req.Body.Bytes.Length > oauth.VcalmMaxRequestBytes)
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


    //A §3.2.1 malformed-input 400 (an RFC 9457 ProblemDetail naming the malformed-value type).
    private static ServerHttpResponse MalformedRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.MalformedValueError,
            "MALFORMED_VALUE_ERROR",
            "The request body could not be parsed as a valid issuance request.");

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }


    //§3.2.1 structural validation of the credential to be issued: a Verifiable Credential carries a
    //non-empty @context, a type that includes VerifiableCredential, an issuer, and at least one
    //credentialSubject (VC-DM §4). A violation is a §3.8 MALFORMED_VALUE_ERROR 400 — the issuer
    //refuses to secure a document that is not a valid credential.
    private static ServerHttpResponse? ValidateCredentialStructure(VerifiableCredential credential)
    {
        if(credential.Context?.Contexts is not { Count: > 0 })
        {
            return MalformedCredentialRequest("The credential must have a non-empty '@context'.");
        }

        if(credential.Type is not { Count: > 0 } type
            || !type.Contains("VerifiableCredential", StringComparer.Ordinal))
        {
            return MalformedCredentialRequest(
                "The credential 'type' must be a non-empty array containing 'VerifiableCredential'.");
        }

        if(string.IsNullOrEmpty(credential.Issuer?.Id))
        {
            return MalformedCredentialRequest("The credential must have an 'issuer'.");
        }

        if(credential.CredentialSubject is not { Count: > 0 })
        {
            return MalformedCredentialRequest("The credential must have a 'credentialSubject'.");
        }

        return null;
    }


    //A §3.2.1 / §3.8 MALFORMED_VALUE_ERROR 400 carrying the specific structural reason the credential
    //could not be issued.
    private static ServerHttpResponse MalformedCredentialRequest(string detail)
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.MalformedValueError,
            "MALFORMED_VALUE_ERROR",
            detail);

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }


    //The §2.4 unknown-option 400, carrying the §3.8 UNKNOWN_OPTION_PROVIDED type.
    private static ServerHttpResponse UnknownOptionRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.UnknownOptionProvided,
            "UNKNOWN_OPTION_PROVIDED",
            "An option that is unknown to or unsupported by the issuer instance was provided to the API call.");

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }


    //The §3.2.1 issuer-mismatch 400: "The provided value of 'issuer' does not match the expected
    //configuration."
    private static ServerHttpResponse IssuerMismatchRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.MalformedValueError,
            "MALFORMED_VALUE_ERROR",
            "The provided value of 'issuer' does not match the expected configuration.");

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }


    //The §3.2.1 both-set credentialId-conflict 400: credentialId and credential.id are both present
    //and differ, an ambiguous identity the instance cannot honour.
    private static ServerHttpResponse CredentialIdConflictRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.MalformedValueError,
            "MALFORMED_VALUE_ERROR",
            "options.credentialId and credential.id are both set and differ. Per §3.2.1, credentialId "
            + "SHOULD NOT be set when credential.id is set; a conflicting pair is an ambiguous identity.");

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }


    //The §3.2.1 Error-Handling 400: the instance is configured to only accept credentials without
    //existing proofs and a pre-proofed credential was provided.
    private static ServerHttpResponse ExistingProofRejectedRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.MalformedValueError,
            "MALFORMED_VALUE_ERROR",
            "The provided credential already contains a proof, and this issuer instance is configured "
            + "to only accept credentials without existing proofs (§3.2.1 Error Handling).");

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }


    //The §3.2.2 410 Gone for a soft-deleted credential whose tombstone the store retained
    //("Gone! There is no data here").
    private static ServerHttpResponse Gone() =>
        ServerHttpResponse.Json(410, string.Empty, WellKnownMediaTypes.Application.Json);
}
