using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Threading;
using Verifiable.Core;
using Verifiable.Server.Diagnostics;
using Verifiable.Server.Pipeline;
using Verifiable.Server.Routing;

namespace Verifiable.Server;

/// <summary>
/// The protocol-neutral endpoint host. Produces a response for an inbound
/// <see cref="IncomingRequest"/> by resolving the tenant and registration, building the
/// per-request endpoint chain, walking it to a matched endpoint, and running that
/// endpoint — stateless short-circuit or stateful PDA flow.
/// </summary>
/// <remarks>
/// <para>
/// The host owns only what every protocol family shares: the time source, the neutral
/// <see cref="Configuration"/> (the endpoint-builder set), the host-generic
/// <see cref="Integration"/> seams the dispatch loop calls, and the per-family
/// integration registry (<see cref="AddIntegration{T}"/> / <see cref="GetIntegration{T}"/>).
/// A protocol family registers its richer integration — carrying its protocol seams,
/// token producers, claim issuers, cryptography, and codecs — through that registry; the
/// host depends on none of it.
/// </para>
/// <para>
/// The application skin produces a typed <see cref="IncomingRequest"/> from the inbound
/// HTTP request and calls <see cref="DispatchAsync"/> with it and an
/// <see cref="ExchangeContext"/>. The library does the rest.
/// </para>
/// </remarks>
[DebuggerDisplay("EndpointServer Validated={IsValidated}")]
public sealed class EndpointServer: IDisposable
{
    private bool Disposed { get; set; }

    private readonly Dictionary<Type, ServerIntegration> integrations = [];


    /// <summary>
    /// The host-generic integration seams the dispatch loop and pipeline call. Required.
    /// A protocol family assigns its <see cref="ServerIntegration"/>-derived integration
    /// here; the same object is typically also registered via <see cref="AddIntegration{T}"/>
    /// so endpoints can reach its protocol seams.
    /// </summary>
    [SuppressMessage("Naming", "CA1721:Property names should not match get methods",
        Justification = "Integration is the host-generic seam group the dispatch loop reads; GetIntegration<T>() retrieves a typed per-family integration from the registry. They are distinct concepts, not a property/accessor pair.")]
    public required ServerIntegration Integration { get; init; }

    /// <summary>
    /// The time source used for expiry, state timestamps, and event timestamps. Defaults
    /// to <see cref="System.TimeProvider.System"/>.
    /// </summary>
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>
    /// The protocol-neutral configuration of the host: the endpoint builders that define
    /// which flows the host supports. Required. Immutable; swap atomically via
    /// <see cref="ApplyConfiguration"/>.
    /// </summary>
    public required ServerConfiguration Configuration
    {
        get => Volatile.Read(ref configuration)!;
        init => configuration = value;
    }

    private ServerConfiguration? configuration;

    /// <summary>
    /// The family action executor that drives effectful work between pure PDA transitions
    /// for stateful flows. Required for flows whose
    /// <see cref="StatefulFlowKind.RequiresActionExecutor"/> is <see langword="true"/>;
    /// stateless and no-action flows leave it null.
    /// </summary>
    public FlowActionExecutorDelegate? ActionExecutor { get; set; }

    /// <summary>
    /// Whether <see cref="Validate"/> has been called successfully.
    /// </summary>
    public bool IsValidated { get; private set; }


    /// <summary>
    /// Registers a per-family integration object, keyed by its concrete type, so endpoints
    /// can reach their family's protocol seams via <see cref="GetIntegration{T}"/>.
    /// </summary>
    /// <typeparam name="T">The concrete integration type.</typeparam>
    /// <param name="integration">The integration object to register.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="integration"/> is null.</exception>
    public void AddIntegration<T>(T integration) where T : ServerIntegration
    {
        ArgumentNullException.ThrowIfNull(integration);
        integrations[typeof(T)] = integration;
    }


    /// <summary>
    /// Returns the registered integration of type <typeparamref name="T"/>.
    /// </summary>
    /// <typeparam name="T">The concrete integration type to retrieve.</typeparam>
    /// <exception cref="InvalidOperationException">
    /// Thrown when no integration of type <typeparamref name="T"/> has been registered.
    /// </exception>
    public T GetIntegration<T>() where T : ServerIntegration
    {
        if(integrations.TryGetValue(typeof(T), out ServerIntegration? integration))
        {
            return (T)integration;
        }

        throw new InvalidOperationException(
            $"No integration of type '{typeof(T).Name}' is registered on this {nameof(EndpointServer)}. "
            + $"Register it with {nameof(AddIntegration)}<{typeof(T).Name}>(...) at construction time.");
    }


    /// <summary>
    /// Validates that the host's required configuration is populated and that the
    /// host-generic integration seams are wired.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the integration is missing required seams or
    /// <see cref="ServerConfiguration.EndpointBuilders"/> is empty.
    /// </exception>
    public void Validate()
    {
        Integration.Validate();

        if(Configuration.EndpointBuilders.Count == 0)
        {
            throw new InvalidOperationException(
                $"{nameof(EndpointServer)} requires at least one entry in {nameof(ServerConfiguration)}.{nameof(ServerConfiguration.EndpointBuilders)}.");
        }

        IsValidated = true;
    }


    /// <summary>
    /// Replaces this host's <see cref="Configuration"/> with the supplied snapshot. The
    /// reference swap is atomic; in-flight dispatches finish on the previous configuration.
    /// </summary>
    /// <param name="configuration">The replacement configuration.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="configuration"/> is null.</exception>
    public void ApplyConfiguration(ServerConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        Volatile.Write(ref this.configuration, configuration);
    }


    /// <summary>
    /// Dispatches an inbound request to the matching endpoint and returns the HTTP
    /// response.
    /// </summary>
    /// <param name="request">The typed request envelope produced by the skin.</param>
    /// <param name="context">The per-request context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async ValueTask<ServerHttpResponse> DispatchAsync(
        IncomingRequest request,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);

        cancellationToken.ThrowIfCancellationRequested();

        using Activity? activity = ServerActivitySource.Source.StartActivity(
            ServerActivityNames.Handle);

        //Place the active host and typed request envelope on the context.
        context.SetServer(this);
        context.SetIncomingRequest(request);

        //Inspection stage 1 of 4 — fires once at dispatch entry on every request.
        await Integration.InspectAsync!(
            new IncomingRequestStage(request), context, cancellationToken)
            .ConfigureAwait(false);

        ServerHttpResponse response;

        //1. Resolve the tenant.
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
                ServerErrors.InvalidRequest, "No tenant identifier resolved for request.");
        }
        else
        {
            //2. Load the registration for this tenant.
            IRegistrationRecord? registration = context.Registration
                ?? await Integration.LoadRegistrationAsync!(
                    tenantId.Value, context, cancellationToken).ConfigureAwait(false);

            if(registration is null)
            {
                response = ServerHttpResponse.NotFound();
            }
            else
            {
                context.SetRegistration(registration);

                activity?.SetTag(ServerTagNames.TenantId, registration.TenantId.Value);
                activity?.SetTag(ServerTagNames.RegistrationId, registration.ClientId);

                //2.5 Resolve per-request policy and place it on the context.
                await Integration.ResolvePolicyAsync!(
                    registration, context, cancellationToken).ConfigureAwait(false);

                //2.6 Resolve the issuer URI for downstream emitters.
                Uri? issuer = Integration.ResolveIssuerAsync is not null
                    ? await Integration.ResolveIssuerAsync(
                        registration, context, cancellationToken).ConfigureAwait(false)
                    : context.Issuer;

                if(issuer is not null) { context.SetIssuer(issuer); }

                //3. Build the registration's active endpoint chain and walk it.
                EndpointChain chain = await EndpointChain.BuildForRequestAsync(
                    registration, context, cancellationToken).ConfigureAwait(false);
                context.SetEndpointChain(chain);

                MatchedEndpoint? matched = await chain.MatchAsync(
                    request.Fields, context, cancellationToken).ConfigureAwait(false);

                if(matched is not null)
                {
                    context.SetMatchPayload(matched.Payload);
                    context.SetCapability(matched.Endpoint.Capability);

                    activity?.SetTag(ServerTagNames.FlowKind, matched.Endpoint.Kind.Name);
                    activity?.SetTag(ServerTagNames.HttpMethod, matched.Endpoint.HttpMethod);
                    activity?.SetTag(ServerTagNames.StartsNewFlow, matched.Endpoint.StartsNewFlow);
                }

                //Inspection stage 2 of 4 — match decision.
                await Integration.InspectAsync!(
                    new MatchedStage(matched?.Endpoint, matched?.Payload),
                    context, cancellationToken).ConfigureAwait(false);

                if(matched is null)
                {
                    response = ServerHttpResponse.NotFound();
                }
                else
                {
                    response = await HandleCoreAsync(
                        matched.Endpoint, request.Fields, context, registration, activity, cancellationToken)
                        .ConfigureAwait(false);
                }
            }
        }

        //Inspection stage 4 of 4 — fired immediately before the response returns.
        await Integration.InspectAsync!(
            new OutgoingResponseStage(response), context, cancellationToken)
            .ConfigureAwait(false);

        activity?.SetTag(
            ServerTagNames.StatusCode,
            response.StatusCode.ToString(CultureInfo.InvariantCulture));

        return response;
    }


    private async ValueTask<ServerHttpResponse> HandleCoreAsync(
        ServerEndpoint endpoint,
        RequestFields fields,
        ExchangeContext context,
        IRegistrationRecord registration,
        Activity? activity,
        CancellationToken cancellationToken)
    {
        //1. Stateless endpoints short-circuit here: no PDA, no persistence.
        if(endpoint.Kind is StatelessFlowKind)
        {
            FlowState statelessSentinel = CreateStatelessSentinel(
                endpoint.Kind, TimeProvider);

            (FlowInput? _, ServerHttpResponse? statelessEarlyExit) =
                await endpoint.BuildInputAsync(
                    fields, context, statelessSentinel, cancellationToken)
                    .ConfigureAwait(false);

            return statelessEarlyExit ?? ServerHttpResponse.ServerError(
                ServerErrors.ServerError,
                "Stateless endpoint did not produce a response.");
        }

        //3. Stateful flow — get current state (fresh for new flows, loaded for continuing).
        FlowState currentState;
        int currentStepCount;
        string flowId;

        if(endpoint.StartsNewFlow)
        {
            if(endpoint.Kind is not StatefulFlowKind statefulKind)
            {
                return ServerHttpResponse.ServerError(
                    ServerErrors.ServerError,
                    $"Endpoint kind '{endpoint.Kind.GetType().Name}' cannot start a flow.");
            }

            flowId = await Integration.GenerateIdentifierAsync!(
                WellKnownServerIdentifierPurposes.FlowId, context, cancellationToken)
                .ConfigureAwait(false);
            context.SetFlowId(flowId);

            (currentState, currentStepCount) = await statefulKind.CreateAsync(
                flowId, TimeProvider).ConfigureAwait(false);

            activity?.AddEvent(new ActivityEvent(ServerEventNames.FlowCreated));
        }
        else
        {
            string externalHandle = endpoint.ExtractCorrelationKey is not null
                ? endpoint.ExtractCorrelationKey(string.Empty, fields, context) ?? string.Empty
                : context.CorrelationKey ?? string.Empty;

            if(string.IsNullOrWhiteSpace(externalHandle))
            {
                return ServerHttpResponse.BadRequest(
                    ServerErrors.InvalidRequest, "Cannot determine correlation key.");
            }

            if(Integration.ResolveCorrelationKeyAsync is not null)
            {
                string? resolved = await Integration.ResolveCorrelationKeyAsync(
                    context.TenantId!.Value, endpoint.Kind, externalHandle, context, cancellationToken)
                    .ConfigureAwait(false);

                if(resolved is null)
                {
                    activity?.AddEvent(new ActivityEvent(ServerEventNames.CorrelationNotFound));
                    activity?.SetTag(ServerTagNames.CorrelationResolved, false);

                    return ServerHttpResponse.BadRequest(
                        ServerErrors.InvalidRequest, "Flow not found or expired.");
                }

                flowId = resolved;
                activity?.AddEvent(new ActivityEvent(ServerEventNames.CorrelationResolved));
                activity?.SetTag(ServerTagNames.CorrelationResolved, true);
            }
            else
            {
                flowId = externalHandle;
            }

            context.SetFlowId(flowId);

            (FlowState? savedState, int savedStepCount) =
                await Integration.LoadFlowStateAsync!(
                    context.TenantId!.Value, flowId, context, cancellationToken).ConfigureAwait(false);

            if(savedState is null)
            {
                return ServerHttpResponse.BadRequest(
                    ServerErrors.InvalidRequest, "Flow not found or expired.");
            }

            DateTimeOffset now = TimeProvider.GetUtcNow();
            if(savedState.ExpiresAt <= now)
            {
                return ServerHttpResponse.BadRequest(
                    ServerErrors.InvalidRequest, "Flow not found or expired.");
            }

            currentState = savedState;
            currentStepCount = savedStepCount;
        }

        //4. Stamp the request time once.
        context.SetVerifiedAt(TimeProvider.GetUtcNow());

        //5. Build the input — effectful work happens here, outside the PDA.
        (FlowInput? input, ServerHttpResponse? earlyExit) =
            await endpoint.BuildInputAsync(
                fields, context, currentState, cancellationToken).ConfigureAwait(false);

        if(earlyExit is not null)
        {
            return earlyExit;
        }

        //6. Step the PDA and drive the effectful loop.
        (FlowState newState, int newStepCount) =
            await FlowRunner.StepWithEffectsAsync(
                currentState,
                currentStepCount,
                input!,
                ActionExecutor,
                context,
                TimeProvider,
                cancellationToken).ConfigureAwait(false);

        activity?.SetTag(ServerTagNames.FlowState, newState.GetType().Name);
        activity?.SetTag(ServerTagNames.FlowStepCount, newStepCount);
        activity?.AddEvent(new ActivityEvent(ServerEventNames.StateTransition));

        //7. Build the response.
        ServerHttpResponse response = endpoint.BuildResponse(
            newState, newState.Kind.Name, context);

        //8. Persist under the internal flowId.
        await Integration.SaveFlowStateAsync!(
            context.TenantId!.Value, flowId, newState, newStepCount, context, cancellationToken)
            .ConfigureAwait(false);

        return response;
    }


    //Sentinel state passed to stateless endpoints' BuildInputAsync to satisfy the
    //non-nullable state parameter. Never persisted, never stepped.
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


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            Disposed = true;
        }
    }
}
