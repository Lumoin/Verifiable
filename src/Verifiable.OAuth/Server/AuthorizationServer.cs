using System.Diagnostics;
using System.Globalization;
using Verifiable.Core.Automata;
using Verifiable.OAuth.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// An authorization server instance that handles OAuth and OID4VP requests,
/// manages client registration lifecycle, and emits events to subscribers.
/// </summary>
/// <remarks>
/// <para>
/// This is the primary type an application developer constructs at startup and
/// registers in the dependency injection container:
/// </para>
/// <code>
/// var options = new AuthorizationServerOptions { ... };
/// options.Validate();
/// var server = new AuthorizationServer(options);
///
/// //Subscribe to registration events for routing table updates, cache
/// //invalidation, audit logging, or message bus bridging.
/// server.Events.Subscribe(myObserver);
///
/// //Register clients — each emits a ClientRegistered event.
/// server.RegisterClient(registration, context);
///
/// //In the ASP.NET endpoint handler:
/// app.MapPost("/my/path/par", async (HttpContext http) =>
/// {
///     var endpoint = endpoints.First(
///         e => e.Capability == ServerCapabilityName.PushedAuthorization);
///     var fields = new RequestFields(http.Request.Form);
///     var context = new RequestContext();
///     return await server.HandleAsync(endpoint, fields, context, http.RequestAborted);
/// });
/// </code>
/// <para>
/// The server does not own routing. The application maps its routes — segments,
/// host headers, tenant identifiers, flat paths — to <see cref="ServerEndpoint"/>
/// records and calls <see cref="HandleAsync"/>. The
/// <see cref="ServerEndpoint.PathTemplate"/> values are advisory documentation,
/// not routing infrastructure.
/// </para>
/// <para>
/// Events are instance-scoped. Multiple <see cref="AuthorizationServer"/> instances
/// in the same process have independent event streams, enabling multi-tenant
/// deployments and isolated test execution.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthorizationServer Validated={Options.IsValidated}")]
public sealed class AuthorizationServer: IDisposable
{
    private readonly EventSubject eventSubject = new();
    private bool Disposed { get; set; }


    /// <summary>
    /// The validated options carrying all I/O delegates.
    /// </summary>
    public AuthorizationServerOptions Options { get; }

    /// <summary>
    /// The instance-scoped event stream for client registration lifecycle events.
    /// Subscribe to receive <see cref="ClientRegistered"/>, <see cref="ClientUpdated"/>,
    /// <see cref="ClientDeregistered"/>, <see cref="CapabilityGranted"/>, and
    /// <see cref="CapabilityRevoked"/> events.
    /// </summary>
    public IObservable<ClientRegistrationEvent> Events => eventSubject;


    /// <summary>
    /// Creates a new authorization server instance with the given options.
    /// Calls <see cref="AuthorizationServerOptions.Validate"/> if not already validated.
    /// </summary>
    /// <param name="options">
    /// The server options carrying all I/O delegates. Must have all required
    /// delegates set.
    /// </param>
    public AuthorizationServer(AuthorizationServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if(!options.IsValidated)
        {
            options.Validate();
        }

        Options = options;
    }


    /// <summary>
    /// Returns the active endpoints for a registration based on its capabilities
    /// and any additional endpoint builders on
    /// <see cref="AuthorizationServerOptions.AdditionalEndpointBuilders"/>.
    /// </summary>
    /// <param name="registration">
    /// The client registration whose capabilities determine which endpoints to build.
    /// </param>
    public IReadOnlyList<ServerEndpoint> GetEndpoints(ClientRegistration registration)
    {
        ArgumentNullException.ThrowIfNull(registration);

        return AuthorizationServerEndpointRegistry.BuildFor(registration, Options);
    }


    /// <summary>
    /// Convenience method that resolves the endpoint by capability and HTTP method,
    /// then calls <see cref="HandleAsync"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Uses <see cref="EndpointMatcher.Find(IReadOnlyList{ServerEndpoint}, ServerCapabilityName, string, RequestFields)"/>
    /// to resolve the endpoint from the registration's active endpoints. When multiple
    /// endpoints share the same capability and method, the
    /// <see cref="ServerEndpoint.MatchesRequest"/> predicate disambiguates using the
    /// request <paramref name="fields"/>.
    /// </para>
    /// <para>
    /// For full control over endpoint resolution — for example, custom routing schemes,
    /// cached endpoint lists, or dynamic capability filtering — call
    /// <see cref="HandleAsync"/> directly with the resolved endpoint.
    /// </para>
    /// </remarks>
    /// <param name="registration">The client registration to resolve endpoints for.</param>
    /// <param name="capability">The capability to match.</param>
    /// <param name="httpMethod">The HTTP method to match.</param>
    /// <param name="fields">The request fields, also used for endpoint disambiguation.</param>
    /// <param name="context">Application-defined request context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public ValueTask<ServerHttpResponse> DispatchAsync(
        ClientRegistration registration,
        ServerCapabilityName capability,
        string httpMethod,
        RequestFields fields,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(context);

        IReadOnlyList<ServerEndpoint> endpoints = GetEndpoints(registration);
        ServerEndpoint? endpoint = EndpointMatcher.Find(endpoints, capability, httpMethod, fields);

        if(endpoint is null)
        {
            return ValueTask.FromResult(ServerHttpResponse.NotFound());
        }

        context.SetRegistration(registration);

        return HandleAsync(endpoint, fields, context, cancellationToken);
    }


    /// <summary>
    /// Handles an inbound request against a resolved <see cref="ServerEndpoint"/>,
    /// driving the PDA lifecycle and returning the HTTP response.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The application resolves the endpoint before calling this method. How the
    /// endpoint is resolved — by path matching, by capability lookup, by route
    /// metadata — is entirely the application's concern.
    /// </para>
    /// <para>
    /// For continuing flows (<see cref="ServerEndpoint.StartsNewFlow"/> is
    /// <see langword="false"/>), the correlation key is extracted by the endpoint's
    /// <see cref="ServerEndpoint.ExtractCorrelationKey"/> delegate if set, or read
    /// from <see cref="RequestContext.CorrelationKey"/> if the application placed it
    /// there from its routing (e.g., a path parameter). At least one must produce a
    /// non-empty key.
    /// </para>
    /// </remarks>
    /// <param name="endpoint">The resolved endpoint to handle the request.</param>
    /// <param name="fields">
    /// The parsed request fields from the HTTP form body or query string.
    /// </param>
    /// <param name="context">
    /// Application-defined request context. The method enriches it with the resolved
    /// <see cref="ClientRegistration"/> and a consistent request timestamp.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async ValueTask<ServerHttpResponse> HandleAsync(
        ServerEndpoint endpoint,
        RequestFields fields,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(context);

        cancellationToken.ThrowIfCancellationRequested();

        using Activity? activity = OAuthActivitySource.Source.StartActivity(
            OAuthActivityNames.Handle);
        activity?.SetTag(OAuthTagNames.EndpointPath, endpoint.PathTemplate);
        activity?.SetTag(OAuthTagNames.FlowKind, endpoint.Kind.Name);
        activity?.SetTag(OAuthTagNames.HttpMethod, endpoint.HttpMethod);
        activity?.SetTag(OAuthTagNames.StartsNewFlow, endpoint.StartsNewFlow);

        ServerHttpResponse response = await HandleCoreAsync(
            endpoint, fields, context, activity, cancellationToken).ConfigureAwait(false);

        activity?.SetTag(OAuthTagNames.StatusCode, response.StatusCode.ToString(CultureInfo.InvariantCulture));

        return response;
    }


    private async ValueTask<ServerHttpResponse> HandleCoreAsync(
        ServerEndpoint endpoint,
        RequestFields fields,
        RequestContext context,
        Activity? activity,
        CancellationToken cancellationToken)
    {

        //1. Resolve registration if not already in context.
        ClientRegistration? registration = context.Registration;
        if(registration is null)
        {
            //Resolve the tenant first. The skin may have placed it on the context
            //already; otherwise the application's ExtractTenantIdAsync delegate
            //reads it from whichever request signal identifies the tenant in this
            //deployment (path segment, subdomain, Host header, mTLS subject, etc.).
            TenantId? tenantId = context.TenantId;
            if(tenantId is null && Options.ExtractTenantIdAsync is not null)
            {
                tenantId = await Options.ExtractTenantIdAsync(
                    context, cancellationToken).ConfigureAwait(false);
                if(tenantId is not null)
                {
                    context.SetTenantId(tenantId.Value);
                }
            }

            if(tenantId is null)
            {
                return ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidRequest, "No tenant identifier resolved for request.");
            }

            registration = await Options.LoadClientRegistrationAsync!(
                tenantId.Value, context, cancellationToken).ConfigureAwait(false);

            if(registration is null)
            {
                return ServerHttpResponse.NotFound();
            }

            context.SetRegistration(registration);
        }
        else if(context.TenantId is null)
        {
            //Pre-resolved registration path — surface its tenant on the context
            //so downstream storage delegates can read context.TenantId uniformly.
            context.SetTenantId(registration.TenantId);
        }

        activity?.SetTag(OAuthTagNames.TenantId, registration.TenantId.Value);
        activity?.SetTag(OAuthTagNames.ClientId, registration.ClientId);

        //2. Check capability.
        bool allowed = await Options.CheckCapabilityAsync(
            registration, endpoint.Capability, context, cancellationToken).ConfigureAwait(false);

        if(!allowed)
        {
            return ServerHttpResponse.Forbidden(
                OAuthErrors.UnauthorizedClient, "Capability not allowed for this client.");
        }

        //3. Stateless endpoints short-circuit here: no PDA, no persistence.
        //The endpoint's BuildInputAsync returns an early-exit response directly.
        //A disposable sentinel state is passed only to satisfy the non-nullable
        //BuildInputDelegate signature; the endpoint ignores it.
        if(endpoint.Kind is StatelessFlowKind)
        {
            OAuthFlowState statelessSentinel = CreateStatelessSentinel(
                endpoint.Kind, Options.TimeProvider);

            (OAuthFlowInput? _, ServerHttpResponse? statelessEarlyExit) =
                await endpoint.BuildInputAsync(
                    fields, context, statelessSentinel, Options, cancellationToken)
                    .ConfigureAwait(false);

            return statelessEarlyExit ?? ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "Stateless endpoint did not produce a response.");
        }

        //4. Stateful flow — get current state (fresh for new flows, loaded for
        //continuing flows). The flowId is the stable internal identifier. It never
        //crosses process boundaries. External handles (request_uri tokens, codes,
        //device_codes) are separate opaque values resolved back to flowId by the
        //application's ResolveCorrelationKeyAsync delegate.
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
                flowId, Options.TimeProvider).ConfigureAwait(false);

            activity?.AddEvent(new ActivityEvent(OAuthEventNames.FlowCreated));
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
            if(Options.ResolveCorrelationKeyAsync is not null)
            {
                string? resolved = await Options.ResolveCorrelationKeyAsync(
                    context.TenantId!.Value, endpoint.Kind, externalHandle, context, cancellationToken)
                    .ConfigureAwait(false);

                if(resolved is null)
                {
                    activity?.AddEvent(new ActivityEvent(OAuthEventNames.CorrelationNotFound));
                    activity?.SetTag(OAuthTagNames.CorrelationResolved, false);
                    return ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Flow not found or expired.");
                }

                flowId = resolved;
                activity?.AddEvent(new ActivityEvent(OAuthEventNames.CorrelationResolved));
                activity?.SetTag(OAuthTagNames.CorrelationResolved, true);
            }
            else
            {
                //No resolve delegate — the external handle IS the flowId.
                //This is valid for flows where the key never changes (e.g.,
                //OID4VP with state = flowId during migration).
                flowId = externalHandle;
            }

            context.SetFlowId(flowId);

            (OAuthFlowState? savedState, int savedStepCount) =
                await Options.LoadFlowStateAsync!(
                    context.TenantId!.Value, flowId, context, cancellationToken).ConfigureAwait(false);

            if(savedState is null)
            {
                return ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidRequest, "Flow not found or expired.");
            }

            //Enforce server-side TTL. ExpiresAt is set on every flow state when the
            //flow is created and propagated through every transition. A loaded state
            //whose ExpiresAt has passed is treated the same as a missing state —
            //the flow is over, the client must start a new one.
            DateTimeOffset now = Options.TimeProvider.GetUtcNow();
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
        context.SetVerifiedAt(Options.TimeProvider.GetUtcNow());

        //5. Build the input — effectful work happens here, outside the PDA.
        //For new flows, BuildInputAsync reads context.FlowId to reference
        //the internal identifier. It generates external handles separately.
        (OAuthFlowInput? input, ServerHttpResponse? earlyExit) =
            await endpoint.BuildInputAsync(
                fields, context, currentState, Options, cancellationToken).ConfigureAwait(false);

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
                Options.ActionExecutor,
                context,
                Options,
                Options.TimeProvider,
                cancellationToken).ConfigureAwait(false);

        activity?.SetTag(OAuthTagNames.FlowState, newState.GetType().Name);
        activity?.SetTag(OAuthTagNames.FlowStepCount, newStepCount);
        activity?.AddEvent(new ActivityEvent(OAuthEventNames.StateTransition));

        //7. Build the response.
        ServerHttpResponse response = endpoint.BuildResponse(
            newState, newState.Kind.Name, context);

        //8. Persist under the internal flowId. The key is always the same
        //for the lifetime of the flow. The application's SaveFlowStateAsync
        //can pattern-match on the state to build secondary indexes
        //(e.g., code → flowId, request_uri_token → flowId).
        await Options.SaveFlowStateAsync!(
            context.TenantId!.Value, flowId, newState, newStepCount, context, cancellationToken)
            .ConfigureAwait(false);

        return response;
    }


    //Sentinel state passed to stateless endpoints' BuildInputAsync to satisfy the
    //non-nullable state parameter. Never persisted, never stepped. Concrete return
    //type lets the compiler avoid virtual dispatch at the caller (CA1859).
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
    public void RegisterClient(ClientRegistration registration, RequestContext context)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        eventSubject.Emit(new ClientRegistered
        {
            ClientId = registration.ClientId,
            TenantId = registration.TenantId,
            OccurredAt = Options.TimeProvider.GetUtcNow(),
            Context = context,
            Registration = registration
        });
    }


    /// <summary>
    /// Emits a <see cref="ClientUpdated"/> event to this instance's
    /// <see cref="Events"/> stream.
    /// </summary>
    public void UpdateClient(
        ClientRegistration previous,
        ClientRegistration current,
        RequestContext context)
    {
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(context);

        eventSubject.Emit(new ClientUpdated
        {
            ClientId = current.ClientId,
            TenantId = current.TenantId,
            OccurredAt = Options.TimeProvider.GetUtcNow(),
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
        ClientRegistration registration,
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
            OccurredAt = Options.TimeProvider.GetUtcNow(),
            Context = context,
            Reason = reason
        });
    }


    /// <summary>
    /// Emits a <see cref="CapabilityGranted"/> event to this instance's
    /// <see cref="Events"/> stream.
    /// </summary>
    public void GrantCapability(
        ClientRegistration registration,
        ServerCapabilityName capability,
        RequestContext context)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        eventSubject.Emit(new CapabilityGranted
        {
            ClientId = registration.ClientId,
            TenantId = registration.TenantId,
            OccurredAt = Options.TimeProvider.GetUtcNow(),
            Context = context,
            Capability = capability
        });
    }


    /// <summary>
    /// Emits a <see cref="CapabilityRevoked"/> event to this instance's
    /// <see cref="Events"/> stream.
    /// </summary>
    public void RevokeCapability(
        ClientRegistration registration,
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
            OccurredAt = Options.TimeProvider.GetUtcNow(),
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
