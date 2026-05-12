using System.Diagnostics;
using System.Globalization;
using System.Threading;
using Verifiable.JCose;

using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.Server.Routing;
namespace Verifiable.OAuth.Server;

/// <summary>
/// An authorization server instance that handles OAuth and OID4VP requests,
/// manages client registration lifecycle, and emits events to subscribers.
/// </summary>
/// <remarks>
/// <para>
/// The Authorization Server is constructed with three groups of integration
/// delegates supplied by the application: <see cref="Integration"/> for tenant
/// resolution, capability resolution, URL composition, registration storage,
/// and flow-state persistence; <see cref="Cryptography"/> for signing,
/// verification, decryption, and JWKS assembly; and <see cref="Codecs"/> for
/// encoding, decoding, hashing, and JWT serialization. Together these groups
/// are everything the library needs to ask of the application — every other
/// concern lives inside the library.
/// </para>
/// <para>
/// The composable surface — <see cref="ServerConfiguration.EndpointBuilders"/>,
/// <see cref="ServerConfiguration.TokenProducers"/>,
/// <see cref="ServerConfiguration.ClaimContributors"/> — lives on
/// <see cref="Configuration"/>, an immutable snapshot that the running server
/// can swap atomically via <see cref="ApplyConfiguration"/>. Endpoint modules
/// can be added or removed, new token producers can be registered, claim
/// contributors can be reordered — each change commits as a new
/// <see cref="ServerConfiguration"/>. <see cref="ActionExecutor"/> remains
/// directly mutable.
/// </para>
/// <para>
/// The application skin produces a typed <see cref="IncomingRequest"/> from
/// the inbound HTTP request and calls <see cref="DispatchAsync"/> with it
/// and a <see cref="RequestContext"/>. The library does the rest: tenant
/// resolution via <see cref="AuthorizationServerIntegration.ExtractTenantIdAsync"/>,
/// registration load via
/// <see cref="AuthorizationServerIntegration.LoadClientRegistrationAsync"/>,
/// chain walk via <see cref="EndpointChain.MatchAsync"/>, and the protocol
/// logic of the matched endpoint.
/// </para>
/// <code>
/// var server = new AuthorizationServer
/// {
///     Integration = new AuthorizationServerIntegration { ... },
///     Cryptography = new AuthorizationServerCryptography { ... },
///     Codecs = new AuthorizationServerCodecs { ... },
///     TimeProvider = TimeProvider.System,
///     Configuration = new ServerConfiguration
///     {
///         EndpointBuilders = new EndpointBuilderSet([
///             AuthCodeEndpoints.Builder,
///             MetadataEndpoints.Builder
///         ]),
///         TokenProducers = TokenProducerSet.Empty,
///         ClaimContributors = ClaimContributorSet.Empty
///     }
/// };
///
/// server.Validate();
/// server.Events.Subscribe(myObserver);
///
/// //In the application skin:
/// var request = new IncomingRequest(
///     Path: req.Path,
///     Method: req.Method,
///     Fields: fields,
///     Headers: headers,
///     RouteValues: routeValues);
/// var context = new RequestContext();
///
/// ServerHttpResponse response = await server.DispatchAsync(
///     request, context, cancellationToken);
/// </code>
/// <para>
/// Events are instance-scoped. Multiple <see cref="AuthorizationServer"/>
/// instances in the same process have independent event streams, enabling
/// multi-tenant deployments and isolated test execution.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthorizationServer Validated={IsValidated}")]
public sealed class AuthorizationServer: IDisposable
{
    private readonly EventSubject eventSubject = new();
    private bool Disposed { get; set; }


    /// <summary>
    /// The application-resolution and storage delegate group. Required.
    /// </summary>
    public required AuthorizationServerIntegration Integration { get; init; }

    /// <summary>
    /// The cryptographic-material delegate group. Required.
    /// </summary>
    public required AuthorizationServerCryptography Cryptography { get; init; }

    /// <summary>
    /// The encoding, decoding, hashing, and serialization delegate group. Required.
    /// </summary>
    public required AuthorizationServerCodecs Codecs { get; init; }

    /// <summary>
    /// The timing policy applied across all artifact-issuance and timing-claim
    /// validation sites in the library. Defaults to
    /// <see cref="TimingPolicy.Default"/> (HAIP 1.0 / FAPI 2.0 aligned).
    /// </summary>
    /// <remarks>
    /// All durations in artifact lifetimes (PAR responses, JAR <c>exp</c>, codes,
    /// tokens) and clock-skew tolerance for inbound timing validation read from
    /// this single source. The library does not embed timing literals outside
    /// <see cref="TimingPolicy"/> and its consumers.
    /// </remarks>
    public TimingPolicy Timings { get; init; } = TimingPolicy.Default;

    /// <summary>
    /// The time source used for expiry, state timestamps, and event timestamps.
    /// Defaults to <see cref="System.TimeProvider.System"/>. Override in tests
    /// with <c>FakeTimeProvider</c>.
    /// </summary>
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>
    /// The composable configuration of the server: endpoint builders that
    /// define which protocol flows the server supports, token producers that
    /// compose token-endpoint responses, and claim contributors that decorate
    /// token payloads. Required.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="Configuration"/> is an immutable snapshot. Mutating the
    /// running server's configuration happens by constructing a new
    /// <see cref="ServerConfiguration"/> and calling
    /// <see cref="ApplyConfiguration"/>; the reference is swapped atomically.
    /// In-flight dispatches that captured the previous configuration finish
    /// on it; new dispatches see the new one.
    /// </para>
    /// <para>
    /// There are no built-in flows. Every flow — Auth Code, OID4VP, JWKS,
    /// Discovery, Federation, CIBA — is a module registered on
    /// <see cref="ServerConfiguration.EndpointBuilders"/>. The application
    /// chooses which modules to include and may swap configurations at runtime
    /// without restarting the server.
    /// </para>
    /// <para>
    /// Library-provided modules: <c>AuthCodeEndpoints.Builder</c>,
    /// <c>Oid4VpEndpoints.Builder</c>, <c>MetadataEndpoints.Builder</c>.
    /// Application-provided modules use the same
    /// <see cref="EndpointBuilderDelegate"/> shape and are treated identically.
    /// </para>
    /// <para>
    /// Library-shipped producers:
    /// <see cref="TokenProducer.Rfc9068AccessToken"/>,
    /// <see cref="TokenProducer.Oidc10IdToken"/>. Applications add their own
    /// via extension blocks on <see cref="TokenProducer"/>.
    /// </para>
    /// </remarks>
    public required ServerConfiguration Configuration
    {
        get => Volatile.Read(ref configuration)!;
        init => configuration = value;
    }

    /// <summary>
    /// Backing field for <see cref="Configuration"/>. Read via
    /// <see cref="Volatile.Read{T}(ref T)"/> to ensure each dispatch observes
    /// a fully published <see cref="ServerConfiguration"/> reference; written
    /// only via the <see cref="Configuration"/> initialiser at construction or
    /// via <see cref="ApplyConfiguration"/>.
    /// </summary>
    private ServerConfiguration? configuration;

    /// <summary>
    /// Drives effectful work between pure PDA transitions — JAR signing, JWE
    /// decryption, token issuance.
    /// </summary>
    /// <remarks>
    /// Required for flows that produce <see cref="OAuthAction"/> values
    /// requiring effectful work between PDA transitions, such as the OID4VP
    /// Verifier flow. The Authorization Code server flow does not use it.
    /// Use <see cref="Verifiable.OAuth.Oid4Vp.HaipOid4VpVerifierExecutor.Create"/>
    /// for the HAIP 1.0 OID4VP Verifier server flow, or supply a custom executor
    /// for other profiles and flow types.
    /// </remarks>
    public OAuthActionExecutor? ActionExecutor { get; set; }

    /// <summary>
    /// The instance-scoped event stream for client registration lifecycle events.
    /// Subscribe to receive <see cref="ClientRegistered"/>,
    /// <see cref="ClientUpdated"/>, <see cref="ClientDeregistered"/>,
    /// <see cref="CapabilityGranted"/>, and <see cref="CapabilityRevoked"/>
    /// events.
    /// </summary>
    public IObservable<ClientRegistrationEvent> Events => eventSubject;

    /// <summary>
    /// Whether <see cref="Validate"/> has been called successfully.
    /// </summary>
    public bool IsValidated { get; private set; }


    /// <summary>
    /// Validates that all required delegates and catalogs are populated.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when one or more required delegates are missing or
    /// <see cref="ServerConfiguration.EndpointBuilders"/> is empty.
    /// </exception>
    public void Validate()
    {
        Integration.Validate();
        Cryptography.Validate();
        Codecs.Validate();

        if(Configuration.EndpointBuilders.Count == 0)
        {
            throw new InvalidOperationException(
                $"{nameof(AuthorizationServer)} requires at least one entry in {nameof(ServerConfiguration)}.{nameof(ServerConfiguration.EndpointBuilders)}.");
        }

        IsValidated = true;
    }


    /// <summary>
    /// Replaces this server's <see cref="Configuration"/> with the supplied
    /// snapshot. The reference swap is atomic; in-flight dispatches that
    /// captured the previous configuration finish on it; new dispatches see
    /// the new one.
    /// </summary>
    /// <param name="configuration">The replacement configuration.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="configuration"/> is <see langword="null"/>.
    /// </exception>
    /// <remarks>
    /// <para>
    /// Use to commit multiple correlated changes — adding a builder, adding a
    /// producer, adding a contributor — atomically. Compose the new
    /// configuration off-line via the
    /// <see cref="ServerConfiguration.WithEndpointBuilders"/>,
    /// <see cref="ServerConfiguration.WithTokenProducers"/>, and
    /// <see cref="ServerConfiguration.WithClaimContributors"/> non-destructive
    /// updates, then commit it through this method.
    /// </para>
    /// </remarks>
    public void ApplyConfiguration(ServerConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        Volatile.Write(ref this.configuration, configuration);
    }


    /// <summary>
    /// Returns the active endpoint chain for a registration and inbound request
    /// based on the registered <see cref="ServerConfiguration.EndpointBuilders"/>,
    /// the registration's capabilities, and any per-request signals each builder
    /// chooses to read from <paramref name="context"/>.
    /// </summary>
    /// <remarks>
    /// The chain is built fresh per request. Builders that gate on per-request
    /// state (feature flags, tenant configuration, the typed
    /// <see cref="IncomingRequest"/> envelope on the context) may produce
    /// different endpoints across calls for the same registration.
    /// </remarks>
    /// <param name="registration">
    /// The client registration whose capabilities determine which endpoints to
    /// build.
    /// </param>
    /// <param name="context">
    /// The per-request context threaded through to each builder.
    /// </param>
    public EndpointChain GetEndpoints(ClientRecord registration, RequestContext context)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        return EndpointChain.BuildForRequest(registration, context, this);
    }


    /// <summary>
    /// Evaluates whether the given client registration is allowed to use a
    /// capability. Uses
    /// <see cref="AuthorizationServerIntegration.IsCapabilityAllowedAsync"/>
    /// when set, otherwise falls back to
    /// <see cref="ClientRecord.IsCapabilityAllowed"/>.
    /// </summary>
    public ValueTask<bool> CheckCapabilityAsync(
        ClientRecord registration,
        ServerCapabilityName capability,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        if(Integration.IsCapabilityAllowedAsync is not null)
        {
            return Integration.IsCapabilityAllowedAsync(
                registration, capability, context, cancellationToken);
        }

        return ValueTask.FromResult(registration.IsCapabilityAllowed(capability));
    }


    /// <summary>
    /// Dispatches an inbound request to the matching endpoint and returns the
    /// HTTP response.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The application skin produces an <see cref="IncomingRequest"/> from
    /// the inbound HTTP request and hands it to this method. The library does
    /// the rest:
    /// </para>
    /// <list type="number">
    ///   <item><description>Place the typed request envelope on
    ///   <paramref name="context"/> via
    ///   <see cref="RequestContextIncomingRequestExtensions.SetIncomingRequest"/>
    ///   so matchers and handlers can read it.</description></item>
    ///   <item><description>Resolve the tenant. The skin may have placed it on
    ///   the context already; otherwise
    ///   <see cref="AuthorizationServerIntegration.ExtractTenantIdAsync"/>
    ///   reads it from whichever signal in the request envelope identifies the
    ///   tenant in this deployment.</description></item>
    ///   <item><description>Load the <see cref="ClientRecord"/> via
    ///   <see cref="AuthorizationServerIntegration.LoadClientRegistrationAsync"/>.</description></item>
    ///   <item><description>Build the registration's active
    ///   <see cref="EndpointChain"/> via <see cref="GetEndpoints"/> and walk it
    ///   via <see cref="EndpointChain.MatchAsync"/>. The chain walks every
    ///   endpoint in order; each matcher reads whatever signals it cares about
    ///   from <paramref name="context"/> (path, method, fields, headers,
    ///   route values, registration capabilities) and returns either a
    ///   non-<see langword="null"/> <see cref="MatchPayload"/> or
    ///   <see langword="null"/>. The first matcher to accept wins.</description></item>
    ///   <item><description>Place the matched payload on the context for the
    ///   handler, and place the matched endpoint's
    ///   <see cref="ServerEndpoint.Capability"/> on the context for post-match
    ///   telemetry.</description></item>
    ///   <item><description>Run the matched endpoint — stateless short-circuit,
    ///   or load state, build input, step PDA, persist, build response.</description></item>
    /// </list>
    /// </remarks>
    /// <param name="request">
    /// The typed request envelope produced by the skin from the HTTP request.
    /// </param>
    /// <param name="context">
    /// The per-request context. Carries pre-populated typed values for endpoints
    /// invoked internally by the application (OID4VP PAR's
    /// <see cref="RequestContextExtensions.TransactionNonce"/> and
    /// <see cref="RequestContextExtensions.PreparedQuery"/>, JAR-fetch's
    /// <see cref="RequestContextExtensions.CorrelationKey"/>) and is the
    /// communication channel between the dispatcher, matchers, and handlers.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async ValueTask<ServerHttpResponse> DispatchAsync(
        IncomingRequest request,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);

        cancellationToken.ThrowIfCancellationRequested();

        using Activity? activity = Diagnostics.OAuthActivitySource.Source.StartActivity(
            Diagnostics.OAuthActivityNames.Handle);

        //Place the typed request envelope on the context. Matchers and handlers
        //read path, method, headers, and route values from here.
        context.SetIncomingRequest(request);

        //Single response variable so the status code tag below covers every
        //return path, including early exits for missing tenant, missing
        //registration, and unmatched chain.
        ServerHttpResponse response;

        //1. Resolve the tenant. The skin may have placed it on the context already;
        //otherwise the application's ExtractTenantIdAsync delegate reads it from
        //whichever request signal identifies the tenant in this deployment.
        TenantId? tenantId = context.TenantId;
        if(tenantId is null && Integration.ExtractTenantIdAsync is not null)
        {
            tenantId = await Integration.ExtractTenantIdAsync(
                context, cancellationToken).ConfigureAwait(false);
            if(tenantId is not null)
            {
                context.SetTenantId(tenantId.Value);
            }
        }

        if(tenantId is null)
        {
            response = ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequest, "No tenant identifier resolved for request.");
        }
        else
        {
            //2. Load the registration for this tenant.
            ClientRecord? registration = context.Registration
                ?? await Integration.LoadClientRegistrationAsync!(
                    tenantId.Value, context, cancellationToken).ConfigureAwait(false);

            if(registration is null)
            {
                response = ServerHttpResponse.NotFound();
            }
            else
            {
                context.SetRegistration(registration);

                activity?.SetTag(Diagnostics.OAuthTagNames.TenantId, registration.TenantId.Value);
                activity?.SetTag(Diagnostics.OAuthTagNames.ClientId, registration.ClientId);

                //2.5 Resolve per-request policy and place it on the context. Matchers,
                //validators, and token producers downstream consult policy via the
                //typed extensions in PolicyRequestContextExtensions.
                await Integration.ResolvePolicyAsync!(
                    registration, context, cancellationToken).ConfigureAwait(false);

                //3. Build the registration's active endpoint chain and walk it.
                //The chain is built fresh per request — builders may gate on
                //per-request signals on the context (feature flags, tenant
                //config, the typed IncomingRequest envelope). The walk does
                //not pre-filter on capability or method; each matcher's body
                //declares its complete acceptance test.
                EndpointChain chain = GetEndpoints(registration, context);
                MatchedEndpoint? matched = await chain.MatchAsync(
                    request.Fields, context, cancellationToken).ConfigureAwait(false);

                if(matched is null)
                {
                    response = ServerHttpResponse.NotFound();
                }
                else
                {
                    //Place the typed match payload on the context so downstream
                    //handlers that consume classification data can pattern-match
                    //to the subtype their endpoint produced.
                    context.SetMatchPayload(matched.Payload);

                    //Place the matched endpoint's capability on the context for
                    //post-match telemetry. Capability is descriptive metadata
                    //under the Phase 4 model; this is the post-match telemetry
                    //hand-off, not a routing input.
                    context.SetCapability(matched.Endpoint.Capability);

                    activity?.SetTag(Diagnostics.OAuthTagNames.FlowKind, matched.Endpoint.Kind.Name);
                    activity?.SetTag(Diagnostics.OAuthTagNames.HttpMethod, matched.Endpoint.HttpMethod);
                    activity?.SetTag(Diagnostics.OAuthTagNames.StartsNewFlow, matched.Endpoint.StartsNewFlow);

                    response = await HandleAsync(
                        matched.Endpoint, request.Fields, context, activity, cancellationToken)
                        .ConfigureAwait(false);
                }
            }
        }

        //Status code tag is set on every return path so observability tooling
        //sees a non-empty value regardless of whether dispatch reached a
        //matched endpoint, exited early for missing tenant/registration, or
        //returned 404 for an unmatched chain.
        activity?.SetTag(
            Diagnostics.OAuthTagNames.StatusCode,
            response.StatusCode.ToString(CultureInfo.InvariantCulture));

        return response;
    }


    private async ValueTask<ServerHttpResponse> HandleAsync(
        ServerEndpoint endpoint,
        RequestFields fields,
        RequestContext context,
        Activity? activity,
        CancellationToken cancellationToken)
    {
        //StatusCode tag is set by the caller (DispatchAsync) on every return
        //path so unmatched-chain and unresolved-tenant cases also carry it.
        return await HandleCoreAsync(
            endpoint, fields, context,
            context.Registration!,
            activity, cancellationToken).ConfigureAwait(false);
    }


    private async ValueTask<ServerHttpResponse> HandleCoreAsync(
        ServerEndpoint endpoint,
        RequestFields fields,
        RequestContext context,
        ClientRecord registration,
        Activity? activity,
        CancellationToken cancellationToken)
    {
        //1. Check capability.
        bool allowed = await CheckCapabilityAsync(
            registration, endpoint.Capability, context, cancellationToken).ConfigureAwait(false);

        if(!allowed)
        {
            return ServerHttpResponse.Forbidden(
                OAuthErrors.UnauthorizedClient, "Capability not allowed for this client.");
        }

        //2. Stateless endpoints short-circuit here: no PDA, no persistence.
        //The endpoint's BuildInputAsync returns an early-exit response directly.
        //A disposable sentinel state is passed only to satisfy the non-nullable
        //BuildInputDelegate signature; the endpoint ignores it.
        if(endpoint.Kind is StatelessFlowKind)
        {
            OAuthFlowState statelessSentinel = CreateStatelessSentinel(
                endpoint.Kind, TimeProvider);

            (OAuthFlowInput? _, ServerHttpResponse? statelessEarlyExit) =
                await endpoint.BuildInputAsync(
                    fields, context, statelessSentinel, this, cancellationToken)
                    .ConfigureAwait(false);

            return statelessEarlyExit ?? ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "Stateless endpoint did not produce a response.");
        }

        //3. Stateful flow — get current state (fresh for new flows, loaded for
        //continuing flows). The flowId is the stable internal identifier. It
        //never crosses process boundaries. External handles (request_uri tokens,
        //codes, device_codes) are separate opaque values resolved back to flowId
        //by the application's ResolveCorrelationKeyAsync delegate.
        OAuthFlowState currentState;
        int currentStepCount;
        string flowId;

        if(endpoint.StartsNewFlow)
        {
            if(endpoint.Kind is not StatefulFlowKind statefulKind)
            {
                return ServerHttpResponse.ServerError(
                    OAuthErrors.ServerError,
                    $"Endpoint kind '{endpoint.Kind.GetType().Name}' cannot start a flow.");
            }

            flowId = Guid.NewGuid().ToString("N");
            context.SetFlowId(flowId);

            (currentState, currentStepCount) = await statefulKind.CreateAsync(
                flowId, TimeProvider).ConfigureAwait(false);

            activity?.AddEvent(new ActivityEvent(Diagnostics.OAuthEventNames.FlowCreated));
        }
        else
        {
            //Extract the external handle from the request.
            string externalHandle = endpoint.ExtractCorrelationKey is not null
                ? endpoint.ExtractCorrelationKey(string.Empty, fields, context) ?? string.Empty
                : context.CorrelationKey ?? string.Empty;

            if(string.IsNullOrWhiteSpace(externalHandle))
            {
                return ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidRequest, "Cannot determine correlation key.");
            }

            //Resolve the external handle to the internal flowId.
            if(Integration.ResolveCorrelationKeyAsync is not null)
            {
                string? resolved = await Integration.ResolveCorrelationKeyAsync(
                    context.TenantId!.Value, endpoint.Kind, externalHandle, context, cancellationToken)
                    .ConfigureAwait(false);

                if(resolved is null)
                {
                    activity?.AddEvent(new ActivityEvent(Diagnostics.OAuthEventNames.CorrelationNotFound));
                    activity?.SetTag(Diagnostics.OAuthTagNames.CorrelationResolved, false);
                    return ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Flow not found or expired.");
                }

                flowId = resolved;
                activity?.AddEvent(new ActivityEvent(Diagnostics.OAuthEventNames.CorrelationResolved));
                activity?.SetTag(Diagnostics.OAuthTagNames.CorrelationResolved, true);
            }
            else
            {
                //No resolve delegate — the external handle IS the flowId.
                flowId = externalHandle;
            }

            context.SetFlowId(flowId);

            (OAuthFlowState? savedState, int savedStepCount) =
                await Integration.LoadFlowStateAsync!(
                    context.TenantId!.Value, flowId, context, cancellationToken).ConfigureAwait(false);

            if(savedState is null)
            {
                return ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidRequest, "Flow not found or expired.");
            }

            //Enforce server-side TTL. ExpiresAt is set on every flow state when
            //the flow is created and propagated through every transition.
            DateTimeOffset now = TimeProvider.GetUtcNow();
            if(savedState.ExpiresAt <= now)
            {
                return ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidRequest, "Flow not found or expired.");
            }

            currentState = savedState;
            currentStepCount = savedStepCount;
        }

        //4. Stamp the request time once so all effectful work uses a consistent
        //timestamp without reading the system clock directly.
        context.SetVerifiedAt(TimeProvider.GetUtcNow());

        //5. Build the input — effectful work happens here, outside the PDA.
        (OAuthFlowInput? input, ServerHttpResponse? earlyExit) =
            await endpoint.BuildInputAsync(
                fields, context, currentState, this, cancellationToken).ConfigureAwait(false);

        if(earlyExit is not null)
        {
            return earlyExit;
        }

        //6. Step the PDA and drive the effectful loop.
        (OAuthFlowState newState, int newStepCount) =
            await FlowRunner.StepWithEffectsAsync(
                currentState,
                currentStepCount,
                input!,
                ActionExecutor,
                context,
                this,
                TimeProvider,
                cancellationToken).ConfigureAwait(false);

        activity?.SetTag(Diagnostics.OAuthTagNames.FlowState, newState.GetType().Name);
        activity?.SetTag(Diagnostics.OAuthTagNames.FlowStepCount, newStepCount);
        activity?.AddEvent(new ActivityEvent(Diagnostics.OAuthEventNames.StateTransition));

        //7. Build the response.
        ServerHttpResponse response = endpoint.BuildResponse(
            newState, newState.Kind.Name, context);

        //8. Persist under the internal flowId. The key is always the same for
        //the lifetime of the flow. The application's SaveFlowStateAsync can
        //pattern-match on the state to build secondary indexes.
        await Integration.SaveFlowStateAsync!(
            context.TenantId!.Value, flowId, newState, newStepCount, context, cancellationToken)
            .ConfigureAwait(false);

        return response;
    }


    //Sentinel state passed to stateless endpoints' BuildInputAsync to satisfy
    //the non-nullable state parameter. Never persisted, never stepped.
    private static FlowFailed CreateStatelessSentinel(
        FlowKind kind, TimeProvider timeProvider)
    {
        DateTimeOffset now = timeProvider.GetUtcNow();
        return new FlowFailed
        {
            FlowId = string.Empty,
            ExpectedIssuer = string.Empty,
            EnteredAt = now,
            ExpiresAt = DateTimeOffset.MaxValue,
            Kind = kind,
            Reason = "Stateless endpoint — BuildInputAsync returns an early-exit response.",
            FailedAt = now
        };
    }


    /// <summary>
    /// Emits a <see cref="ClientRegistered"/> event to this instance's
    /// <see cref="Events"/> stream.
    /// </summary>
    public void RegisterClient(ClientRecord registration, RequestContext context)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        eventSubject.Emit(new ClientRegistered
        {
            ClientId = registration.ClientId,
            TenantId = registration.TenantId,
            OccurredAt = TimeProvider.GetUtcNow(),
            Context = context,
            Registration = registration
        });
    }


    /// <summary>
    /// Emits a <see cref="ClientUpdated"/> event to this instance's
    /// <see cref="Events"/> stream.
    /// </summary>
    public void UpdateClient(
        ClientRecord previous,
        ClientRecord current,
        RequestContext context)
    {
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(context);

        eventSubject.Emit(new ClientUpdated
        {
            ClientId = current.ClientId,
            TenantId = current.TenantId,
            OccurredAt = TimeProvider.GetUtcNow(),
            Context = context,
            Previous = previous,
            Current = current
        });
    }


    /// <summary>
    /// Emits a <see cref="ClientDeregistered"/> event to this instance's
    /// <see cref="Events"/> stream.
    /// </summary>
    public void DeregisterClient(
        ClientRecord registration,
        string reason,
        RequestContext context)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        ArgumentNullException.ThrowIfNull(context);

        eventSubject.Emit(new ClientDeregistered
        {
            ClientId = registration.ClientId,
            TenantId = registration.TenantId,
            OccurredAt = TimeProvider.GetUtcNow(),
            Context = context,
            Reason = reason
        });
    }


    /// <summary>
    /// Emits a <see cref="CapabilityGranted"/> event to this instance's
    /// <see cref="Events"/> stream.
    /// </summary>
    public void GrantCapability(
        ClientRecord registration,
        ServerCapabilityName capability,
        RequestContext context)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        eventSubject.Emit(new CapabilityGranted
        {
            ClientId = registration.ClientId,
            TenantId = registration.TenantId,
            OccurredAt = TimeProvider.GetUtcNow(),
            Context = context,
            Capability = capability
        });
    }


    /// <summary>
    /// Emits a <see cref="CapabilityRevoked"/> event to this instance's
    /// <see cref="Events"/> stream.
    /// </summary>
    public void RevokeCapability(
        ClientRecord registration,
        ServerCapabilityName capability,
        string reason,
        RequestContext context)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        ArgumentNullException.ThrowIfNull(context);

        eventSubject.Emit(new CapabilityRevoked
        {
            ClientId = registration.ClientId,
            TenantId = registration.TenantId,
            OccurredAt = TimeProvider.GetUtcNow(),
            Context = context,
            Capability = capability,
            Reason = reason
        });
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            eventSubject.Complete();
            Disposed = true;
        }
    }


    //Instance-scoped copy-on-write event subject. Each AuthorizationServer
    //has its own — no static state, no cross-test interference.
    private sealed class EventSubject: IObservable<ClientRegistrationEvent>
    {
        private volatile IObserver<ClientRegistrationEvent>[] observers = [];
        private readonly object gate = new();


        public IDisposable Subscribe(IObserver<ClientRegistrationEvent> observer)
        {
            ArgumentNullException.ThrowIfNull(observer);

            lock(gate)
            {
                IObserver<ClientRegistrationEvent>[] current = observers;
                IObserver<ClientRegistrationEvent>[] updated =
                    new IObserver<ClientRegistrationEvent>[current.Length + 1];
                current.CopyTo(updated, 0);
                updated[current.Length] = observer;
                observers = updated;
            }

            return new Subscription(this, observer);
        }


        public void Emit(ClientRegistrationEvent value)
        {
            IObserver<ClientRegistrationEvent>[] current = observers;
            foreach(IObserver<ClientRegistrationEvent> observer in current)
            {
                observer.OnNext(value);
            }
        }


        public void Complete()
        {
            IObserver<ClientRegistrationEvent>[] current = observers;
            foreach(IObserver<ClientRegistrationEvent> observer in current)
            {
                observer.OnCompleted();
            }
        }


        private void Remove(IObserver<ClientRegistrationEvent> observer)
        {
            lock(gate)
            {
                IObserver<ClientRegistrationEvent>[] current = observers;
                int index = Array.IndexOf(current, observer);
                if(index < 0)
                {
                    return;
                }

                IObserver<ClientRegistrationEvent>[] updated =
                    new IObserver<ClientRegistrationEvent>[current.Length - 1];
                Array.Copy(current, 0, updated, 0, index);
                Array.Copy(current, index + 1, updated, index, current.Length - index - 1);
                observers = updated;
            }
        }


        private sealed class Subscription(
            EventSubject subject,
            IObserver<ClientRegistrationEvent> observer): IDisposable
        {
            private bool disposed;

            public void Dispose()
            {
                if(!disposed)
                {
                    subject.Remove(observer);
                    disposed = true;
                }
            }
        }
    }
}
