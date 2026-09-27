using System.Text;
using Verifiable.Core;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.JCose;

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
/// <see cref="VcalmProblemTypes.UnknownOptionProvided"/> type). An option value the holder cannot
/// process is refused the same way: a value that is not a string, a selective pointer that is not a
/// JSON pointer, or a proof type, cryptosuite, purpose or verification method this instance does not
/// sign with.
/// </para>
/// </remarks>
public static class VcalmHolderEndpoints
{
    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static EndpointBuilderDelegate Builder { get; } = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        EndpointServer? server = context.RequestServer;
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

            //§3.5.2 create-presentation materializes only when the parse seam, the signing
            //configuration, and the §3.4.3.2 channel-domain seam are all wired — the anti-replay MUST
            //("Holder implementations MUST ensure that the domain specified by the verifier matches the
            //domain used for the current channel of communication") needs the channel's own domain to
            //enforce, the same required-seam shape the §3.6 coordinator routes use.
            if(server?.Vcalm().ParseVcalmCreatePresentationAsync is not null
                && (server?.Vcalm().VcalmPresentationSigning is not null
                    || server?.Vcalm().ResolveVcalmPresentationSigningAsync is not null)
                && server?.Vcalm().ResolveVcalmChannelDomainAsync is not null)
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


    /// <summary>
    /// Builds the endpoint for §3.5.1 POST /credentials/derive.
    /// The handler uses the admitted request wiring for its parser and application delegates.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/">Credential lifecycle API</see>.
    /// </summary>
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
                EndpointServer server = context.RequestServer!;
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

                //§3.5.1 "selectivePointers [array]": "An array of JSON pointers specifying the selectively
                //disclosed information. Each item in the selectivePointers array MUST be a string." An item
                //that is not a JSON pointer is an option value this holder cannot process (§2.4), refused
                //before any derivation rather than skipped, through the same check the holder service
                //itself enforces.
                if(!VcalmHolderService.AreAllJsonPointers(request.SelectivePointers))
                {
                    return (null, UnknownOptionRequest());
                }

                //§3.5.1: derivation needs a base-proofed credential. A credential that carries no
                //embedded proof is not a derivable ecdsa-sd-2023 base credential — a §3.5.1 400.
                if(request.Credential is null || request.Credential.Proof is not { Count: > 0 })
                {
                    return (null, NonDerivableRequest());
                }

                //§2.4: "Implementations MUST throw an error if an endpoint receives data ... that it does not
                //understand or know how to process." The derived proof is built from the base proof's own
                //members, so a base proof lacking a Data Integrity §4.4 mandatory member is refused before
                //any signing instead of being carried into the derived credential, through the same check the
                //holder service itself enforces.
                if(!VcalmHolderService.HasCompleteBaseProofs(request.Credential))
                {
                    return (null, IncompleteInputProofRequest());
                }

                return (null, await DeriveAsync(server, request, context, ct).ConfigureAwait(false));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Builds the endpoint for §3.5.2 POST /presentations.
    /// The handler uses the admitted request wiring for its parser and application delegates.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/">Credential lifecycle API</see>.
    /// </summary>
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
                EndpointServer server = context.RequestServer!;
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

                //§2.4: "Implementations MUST throw an error if an endpoint receives data, options, or option
                //values that it does not understand or know how to process." The §3.5.2 presentation schema says
                //"The document MAY include an embedded proof.", and this holder processes none: an embedded proof
                //would be signed over and then replaced by the new proof, which then never verifies. A presentation
                //carrying a proof member is refused before any signing, through the same check the holder service
                //itself enforces. The parser records a proof member of any JSON kind, null included, which the
                //typed presentation cannot show once a null member has been dropped.
                if(request.HasProofMember || VcalmHolderService.HasEmbeddedProof(request.Presentation))
                {
                    return (null, EmbeddedProofRequest());
                }

                //§2.4: "Implementations MUST throw an error if an endpoint receives data ... that it does not
                //understand or know how to process." The presentation proof covers every contained credential's
                //proofs, so a contained proof lacking a Data Integrity §4.4 mandatory member is refused before any
                //signing instead of being re-serialized and signed over, through the same check the holder service
                //itself enforces.
                if(!VcalmHolderService.HasCompleteInputProofs(request.Presentation))
                {
                    return (null, IncompleteInputProofRequest());
                }

                //§3.5.2: a presentation proof binds an anti-replay challenge and a domain (VC-DM 2.0
                //§4.13). A request that omits either cannot produce a valid presentation proof — a 400.
                if(string.IsNullOrEmpty(request.Options.Challenge) || string.IsNullOrEmpty(request.Options.Domain))
                {
                    return (null, MissingChallengeOrDomainRequest());
                }

                //§3.4.3.2 holder anti-replay: "Holder implementations MUST ensure that the domain
                //specified by the verifier matches the domain used for the current channel of
                //communication." The seam is REQUIRED for this route to materialize at all (the Builder
                //gate above), so it is always wired here; a channel it cannot determine, or one that
                //names a verifier other than the request's own domain (a relayed / replayed presentation
                //request), both refuse fail-closed under Data Integrity's domain-mismatch type — the
                //request itself is well-formed, so neither is a malformed-value 400.
                string? channelDomain = await vcalm.ResolveVcalmChannelDomainAsync!(context, ct).ConfigureAwait(false);
                if(channelDomain is null)
                {
                    return (null, UnknownChannelDomainRequest());
                }

                if(!string.Equals(channelDomain, request.Options.Domain, StringComparison.Ordinal))
                {
                    return (null, ChannelDomainMismatchRequest(request.Options.Domain!, channelDomain));
                }

                return (null, await CreatePresentationAsync(server, request, context, ct).ConfigureAwait(false));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Builds the endpoint for §3.5.3 GET /presentations.
    /// The handler uses the admitted request wiring for its parser and application delegates.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/">Credential lifecycle API</see>.
    /// </summary>
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
                EndpointServer server = context.RequestServer!;
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


    /// <summary>
    /// Builds the endpoint for §3.5.4 GET /presentations/{id}.
    /// The handler uses the admitted request wiring for its parser and application delegates.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/">Credential lifecycle API</see>.
    /// </summary>
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
                EndpointServer server = context.RequestServer!;
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


    /// <summary>
    /// Builds the endpoint for §3.5.5 DELETE /presentations/{id}.
    /// The handler uses the admitted request wiring for its parser and application delegates.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/">Credential lifecycle API</see>.
    /// </summary>
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
                EndpointServer server = context.RequestServer!;
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


    /// <summary>
    /// The §3.5.1 derive: composes the selective-disclosure derive surface and returns the 201 derived credential.
    /// The §3.5.1 201 body is the derived credential object itself (the specification's response form is
    /// "@context...id...type...issuer...proof"), not a wrapping <c>{verifiableCredential}</c> envelope.
    /// </summary>
    /// <param name="server">The host, for the derivation wiring.</param>
    /// <param name="request">The parsed derive request.</param>
    /// <param name="context">The per-request context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
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


    /// <summary>
    /// The §3.5.2 create-presentation: binds the request's challenge, domain and created (the instance clock when
    /// <c>created</c> is omitted), signs the presentation under the instance's configured verification method,
    /// persists it under its id, and returns the 201 <c>{verifiablePresentation}</c> body. An option value the holder
    /// cannot process is refused before anything is signed: a <c>type</c>, <c>cryptosuite</c>, <c>proofPurpose</c> or
    /// <c>verificationMethod</c> other than the one this instance signs with is answered as an unknown option
    /// (<see cref="AreOptionValuesProcessable"/>), and a <c>created</c> that is not a dateTimeStamp as a malformed
    /// value, never replaced by the clock.
    /// </summary>
    /// <param name="server">The host, for the time provider, the identifier seam and the signing wiring.</param>
    /// <param name="request">The parsed create-presentation request.</param>
    /// <param name="context">The per-request context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
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

        //§2.4: "Implementations MUST throw an error if an endpoint receives data, options, or option values
        //that it does not understand or know how to process.", and "any given instance configuration MAY
        //prohibit client use of some options properties". A proof type, cryptosuite, purpose or verification
        //method this instance does not sign with would name a proof it cannot produce, so the request is
        //refused before anything is signed.
        if(!AreOptionValuesProcessable(options, signing))
        {
            return UnknownOptionRequest();
        }

        //§3.5.2 created: "The date and time of the proof (with a maximum accuracy in seconds). Default
        //current system time." Data Integrity §2.1 requires a dateTimeStamp, a time zone included; its MAY
        //to consume a value serialized without an offset is not taken, so a value that does not parse is
        //refused rather than replaced by the clock. The proof writes the instant to the second.
        DateTimeOffset requestedCreated = default;
        if(options.Created is not null && !DateTimeStampFormat.TryParse(options.Created, out requestedCreated))
        {
            return MalformedCreatedRequest();
        }

        DateTime proofCreated = options.Created is null
            ? server.TimeProvider.GetUtcNow().UtcDateTime
            : requestedCreated.UtcDateTime;

        //§3.5.2 verificationMethod: "If omitted, a default verification method will be used." A present value
        //equals that default (checked above), so the proof always names the method whose key signs it.
        DataIntegritySecuredPresentation secured = await VcalmHolderService.CreatePresentationAsync(
            request.Presentation!,
            options.Challenge!,
            options.Domain!,
            signing.DefaultVerificationMethodId,
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


    /// <summary>
    /// Whether every present §3.5.2 proof option names what this instance produces: a <c>type</c> of
    /// <see cref="DataIntegrityProof.DataIntegrityProofType"/>, the configured suite's
    /// <see cref="CryptosuiteInfo.CryptosuiteName"/>, a <c>proofPurpose</c> of <see cref="AuthenticationMethod.Purpose"/>
    /// (the purpose the presentation signer writes and a presentation proof is verified under) and the configured
    /// <see cref="VcalmPresentationSigning.DefaultVerificationMethodId"/> (the method whose key signs the proof). An
    /// absent option is always processable; a present one naming anything else is an option value the holder cannot
    /// process (<see href="https://www.w3.org/TR/vcalm-1.0/#options">§2.4</see>), compared ordinally.
    /// </summary>
    /// <param name="options">The parsed create-presentation options.</param>
    /// <param name="signing">The presentation-signing configuration resolved for the request's tenant.</param>
    /// <returns><see langword="true"/> when every present value is one this instance produces; otherwise <see langword="false"/>.</returns>
    private static bool AreOptionValuesProcessable(VcalmCreatePresentationOptions options, VcalmPresentationSigning signing) =>
        options switch
        {
            { Type: { } type } when !string.Equals(type, DataIntegrityProof.DataIntegrityProofType, StringComparison.Ordinal) => false,
            { Cryptosuite: { } cryptosuite } when !string.Equals(cryptosuite, signing.Cryptosuite.CryptosuiteName, StringComparison.Ordinal) => false,
            { ProofPurpose: { } proofPurpose } when !string.Equals(proofPurpose, AuthenticationMethod.Purpose, StringComparison.Ordinal) => false,
            { VerificationMethod: { } verificationMethod } when !string.Equals(verificationMethod, signing.DefaultVerificationMethodId, StringComparison.Ordinal) => false,
            _ => true
        };


    /// <summary>
    /// Reads the <c>{id}</c> path segment the §3.5.4 / §3.5.5 matcher extracted and carried on the match payload. A
    /// skin that did template routing (<c>/presentations/{presentationId}</c>) populates the same id on the request's
    /// route values, which the matcher also honours.
    /// </summary>
    /// <param name="context">The per-request context carrying the match payload.</param>
    /// <returns>The unescaped presentation id, or <see langword="null"/> when the matcher carried none.</returns>
    private static string? ExtractPresentationId(ExchangeContext context)
    {
        if(context.MatchPayload is VcalmPresentationIdMatchPayload payload && !string.IsNullOrEmpty(payload.PresentationId))
        {
            return Uri.UnescapeDataString(payload.PresentationId);
        }

        return null;
    }


    /// <summary>The shared exact matcher: the given method to this endpoint's resolved path.</summary>
    /// <param name="context">The per-request context carrying the incoming request.</param>
    /// <param name="endpoint">The endpoint whose resolved path the request must equal.</param>
    /// <param name="method">The HTTP method the request must carry.</param>
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


    /// <summary>
    /// The §3.5.4 / §3.5.5 path matcher: the given method to a path that is the holder's resolved
    /// <c>/presentations</c> collection path plus a single non-empty trailing <c>{id}</c> segment. The resolved URI is
    /// the collection path; the request adds the id. A skin that did template routing populates the id on the route
    /// values, which are honoured first.
    /// </summary>
    /// <param name="context">The per-request context carrying the incoming request.</param>
    /// <param name="endpoint">The endpoint whose resolved path is the collection path.</param>
    /// <param name="method">The HTTP method the request must carry.</param>
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


    /// <summary>
    /// Whether <paramref name="requestPath"/> is <paramref name="collectionPath"/> followed by a slash and a single
    /// non-empty segment: strips the query and fragment, then checks the prefix and that exactly one non-empty
    /// trailing segment remains.
    /// </summary>
    /// <param name="requestPath">The incoming request path.</param>
    /// <param name="collectionPath">The resolved collection path.</param>
    /// <param name="segment">The trailing segment when the path matches; otherwise the empty string.</param>
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


    /// <summary>
    /// The §2.4 request-boundary MUSTs for the §3.5.1 / §3.5.2 body, mirroring the issuer and the verifier: a body
    /// MUST be present, within the configured size cap (else 413), and <c>application/json</c> (else 400).
    /// </summary>
    /// <param name="context">The per-request context carrying the incoming request.</param>
    /// <param name="server">The host, for the configured size cap.</param>
    /// <param name="requestBody">The UTF-8-decoded body when the boundary holds; otherwise the empty string.</param>
    /// <returns>The refusal response, or <see langword="null"/> when the boundary holds.</returns>
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


    /// <summary>
    /// Compares the request content type to <c>application/json</c> case-insensitively, ignoring any media type
    /// parameters (e.g. <c>; charset=utf-8</c>) per RFC 9110 §8.3.1.
    /// </summary>
    /// <param name="contentType">The request's content type.</param>
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


    /// <summary>A §3.5.1 / §3.5.2 malformed-input 400: an RFC 9457 ProblemDetail naming the malformed-value type.</summary>
    private static ServerHttpResponse MalformedRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.MalformedValueError,
            "MALFORMED_VALUE_ERROR",
            "The request body could not be parsed as a valid presenting request.");

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }


    /// <summary>The §2.4 unknown-option 400, carrying the §3.8 UNKNOWN_OPTION_PROVIDED type.</summary>
    private static ServerHttpResponse UnknownOptionRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.UnknownOptionProvided,
            "UNKNOWN_OPTION_PROVIDED",
            "An option that is unknown to or unsupported by the holder instance was provided to the API call.");

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }


    /// <summary>
    /// The §3.5.1 non-derivable-credential 400: the supplied credential carries no ecdsa-sd-2023 base proof to derive
    /// from.
    /// </summary>
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


    /// <summary>
    /// The §3.5.1 / §3.5.2 incomplete-input-proof 400: an input proof lacks a member
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see> requires of
    /// every proof, refused before any signing under the §2.4 rule that an endpoint MUST throw an error on data
    /// it does not understand or know how to process.
    /// </summary>
    private static ServerHttpResponse IncompleteInputProofRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.MalformedValueError,
            "MALFORMED_VALUE_ERROR",
            VcalmVerificationService.IncompleteInputProofDetail);

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }


    /// <summary>
    /// The §3.5.2 embedded-proof 400: the input presentation carries its own <c>proof</c> member, which this holder does
    /// not process, so it is refused before any signing under the
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">§2.4</see> rule that an endpoint MUST throw an error on data it
    /// does not understand or know how to process. It answers the way the issuer's
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#issue-credential">§3.2.1</see> Error Handling configuration answers a
    /// credential that already carries proofs: with the <see cref="VcalmProblemTypes.MalformedValueError"/> type and the
    /// <see cref="VcalmHolderService.EmbeddedProofDetail"/> detail.
    /// </summary>
    private static ServerHttpResponse EmbeddedProofRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.MalformedValueError,
            "MALFORMED_VALUE_ERROR",
            VcalmHolderService.EmbeddedProofDetail);

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }


    /// <summary>
    /// The §3.5.2 malformed-created 400: the request's <c>options.created</c> is not the dateTimeStamp
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#proofs">Data Integrity §2.1</see> requires of a proof's
    /// <c>created</c> ("MUST be specified as an [XMLSCHEMA11-2] dateTimeStamp string"). The holder does not take that
    /// clause's MAY to consume a value serialized without an offset, and never replaces a value it could not read by
    /// the clock, so the request is refused under the <see href="https://www.w3.org/TR/vcalm-1.0/#options">§2.4</see>
    /// rule that an endpoint MUST throw an error on an option value it does not know how to process, with the
    /// <see cref="VcalmProblemTypes.MalformedValueError"/> type.
    /// </summary>
    private static ServerHttpResponse MalformedCreatedRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.MalformedValueError,
            "MALFORMED_VALUE_ERROR",
            "The options.created value is not a dateTimeStamp: a date and time to the second, optionally with "
            + "fractional seconds, followed by Z or a time zone offset such as +01:00.");

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }


    /// <summary>
    /// The §3.5.2 missing-challenge-or-domain 400: a presentation proof binds an anti-replay challenge and a domain
    /// (VC Data Model 2.0 §4.13), so a request omitting either cannot produce a valid proof.
    /// </summary>
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


    /// <summary>
    /// The §3.4.3.2 channel-domain-mismatch 400: the current communication channel's domain the wired seam resolved
    /// does not match the request's <c>options.domain</c>. That is a relayed or replayed presentation request, so the
    /// holder refuses to sign under Data Integrity's domain-mismatch type
    /// (<see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>) — the request
    /// itself is well-formed, so this is never <see cref="VcalmProblemTypes.MalformedValueError"/>.
    /// </summary>
    /// <param name="requestedDomain">The verifier domain the request asked the presentation proof to bind.</param>
    /// <param name="channelDomain">The current communication channel's domain the wired seam resolved.</param>
    private static ServerHttpResponse ChannelDomainMismatchRequest(string requestedDomain, string channelDomain)
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.InvalidDomainError,
            "INVALID_DOMAIN_ERROR",
            $"The request's options.domain '{requestedDomain}' does not match the current communication "
            + $"channel's domain '{channelDomain}'; a §3.4.3.2 holder refuses to sign a presentation whose "
            + "domain names a verifier other than the one it is communicating with (anti-replay).");

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }


    /// <summary>
    /// The §3.4.3.2 unknown-channel-domain 400: the wired channel-domain seam could not determine the current
    /// communication channel's domain for this request. A holder cannot confirm the verifier identity it is
    /// communicating with, so it refuses to sign fail-closed under Data Integrity's domain-mismatch type
    /// (<see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>) — the request
    /// itself is well-formed, so this is never <see cref="VcalmProblemTypes.MalformedValueError"/>.
    /// </summary>
    private static ServerHttpResponse UnknownChannelDomainRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.InvalidDomainError,
            "INVALID_DOMAIN_ERROR",
            "The current communication channel's domain could not be determined; a §3.4.3.2 holder "
            + "refuses to sign a presentation whose verifier identity it cannot confirm (anti-replay).");

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }


    /// <summary>
    /// The §3.5.4 410 Gone for a soft-deleted presentation whose tombstone the store retained ("Gone! There is no data
    /// here").
    /// </summary>
    private static ServerHttpResponse Gone() =>
        ServerHttpResponse.Json(410, string.Empty, WellKnownMediaTypes.Application.Json);
}
