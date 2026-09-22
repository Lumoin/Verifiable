using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
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
    /// <summary>Protects admission counts, the alteration queue, and construction validation.</summary>
    private object AdmissionLock { get; } = new();


    /// <summary>Alterations in the order their requests acquired admission ownership.</summary>
    private Queue<AlterationRequest> Alterations { get; } = new();


    /// <summary>Requests arriving after the active drain has decided to abandon its window.</summary>
    private Queue<AlterationRequest> PendingAlterations { get; } = new();


    /// <summary>Every component attached to this view, including replaced construction containers.</summary>
    private ConcurrentDictionary<WiringComponent, byte> AttachedComponents { get; } = new(ReferenceEqualityComparer.Instance);


    /// <summary>Weak references permit disposal to detach retained published and discarded views without retaining their graphs.</summary>
    private List<WeakReference<EndpointServer>> OwnedViews { get; } = [];


    /// <summary>The published request view; this field is a Volatile target for atomic publication after requests drain.</summary>
    private EndpointServer? publishedWiring;


    /// <summary>The serving owner of a fixed request view.</summary>
    private EndpointServer? Owner { get; set; }


    /// <summary>The stable server identity shared by its candidate and admitted views.</summary>
    internal EndpointServer WiringOwner => Owner ?? this;


    /// <summary>The primary integration supplied during construction.</summary>
    private ServerIntegration InitialIntegration { get; set; } = null!;


    /// <summary>The construction configuration.</summary>
    private ServerConfiguration InitialConfiguration { get; set; } = null!;


    /// <summary>The construction action bridge.</summary>
    private FlowActionExecutorDelegate? InitialActionExecutor { get; set; }


    /// <summary>The family integrations belonging to this construction or fixed view.</summary>
    private Dictionary<Type, ServerIntegration> Integrations { get; } = [];


    /// <summary>Whether this instance has accepted a request or published an alteration.</summary>
    private bool IsServing { get; set; }


    /// <summary>Whether the alteration worker owns admission.</summary>
    private bool IsAltering { get; set; }


    /// <summary>Whether this instance has been disposed.</summary>
    private bool IsDisposed { get; set; }


    /// <summary>Whether the current wiring passed structural validation.</summary>
    private bool HasValidatedWiring
    {
        get => Volatile.Read(ref field);
        set => Volatile.Write(ref field, value);
    }


    /// <summary>The count of admitted requests that have not released their lease.</summary>
    private int InFlightCount { get; set; }


    /// <summary>Completion of all requests admitted before admission closed.</summary>
    private TaskCompletionSource? DrainCompletion { get; set; }


    /// <summary>Completion of the queued alterations holding new arrivals.</summary>
    private TaskCompletionSource? AdmissionCompletion { get; set; }


    /// <summary>The bounded drain task whose terminal outcome seals this window's membership.</summary>
    private Task? DrainWait { get; set; }


    /// <summary>
    /// The primary host seams in the current wiring. A request retains its admitted reference.
    /// A derived protocol integration must also be registered under its concrete family type.
    /// </summary>
    [SuppressMessage("Naming", "CA1721:Property names should not match get methods",
        Justification = "Integration is the primary host projection; GetIntegration<T> retrieves a protocol family.")]
    public required ServerIntegration Integration
    {
        get => Volatile.Read(ref publishedWiring)?.Integration ?? InitialIntegration;
        init
        {
            ArgumentNullException.ThrowIfNull(value);
            InitialIntegration = value;
            value.Attach(this, InvalidateValidation);
        }
    }


    /// <summary>
    /// The clock shared by the host and its request views. The application owns its synchronization;
    /// requests may observe different timestamps at different processing stages.
    /// </summary>
    public required TimeProvider TimeProvider { get; init; }


    /// <summary>
    /// The immutable endpoint membership and admission policy retained at request admission.
    /// Serving replacements belong to <see cref="RequestAlterationAsync"/>.
    /// </summary>
    public required ServerConfiguration Configuration
    {
        get => Volatile.Read(ref publishedWiring)?.Configuration ?? InitialConfiguration;
        init => InitialConfiguration = value;
    }


    /// <summary>
    /// The action bridge retained for every effect in an admitted request. A null bridge selects
    /// single-step execution. A serving setter throws; edit the alteration candidate instead.
    /// </summary>
    public FlowActionExecutorDelegate? ActionExecutor
    {
        get => Volatile.Read(ref publishedWiring) is EndpointServer wiring ? wiring.InitialActionExecutor : InitialActionExecutor;
        set
        {
            lock(AdmissionLock)
            {
                EnsureConstruction(nameof(ActionExecutor));
                InitialActionExecutor = value;
            }
        }
    }


    /// <summary>
    /// Whether the current wiring has been validated since its last edit and admission is open.
    /// An alteration temporarily clears this value; rejection retains the validated live wiring.
    /// </summary>
    public bool IsValidated
    {
        get
        {
            lock(AdmissionLock)
            {

                return HasValidatedWiring && !IsAltering;
            }
        }
    }


    /// <summary>
    /// Registers a family during construction. A serving call throws a named configuration fault;
    /// use the candidate's registry in <see cref="RequestAlterationAsync"/>.
    /// </summary>
    /// <typeparam name="T">The protocol family's integration type.</typeparam>
    /// <param name="integration">The integration sharing this composition's lifecycle.</param>
    public void AddIntegration<T>(T integration) where T : ServerIntegration
    {
        lock(AdmissionLock)
        {
            ArgumentNullException.ThrowIfNull(integration);
            EnsureConstruction(nameof(AddIntegration));
            integration.Attach(this, InvalidateValidation);
            Integrations[typeof(T)] = integration;
        }
    }


    /// <summary>Registers an adopted candidate family and replaces the matching primary alias together.</summary>
    /// <typeparam name="T">The registry key supplied by the alteration callback.</typeparam>
    /// <param name="integration">The independent adopted container.</param>
    internal void AddCandidateIntegration<T>(T integration) where T : ServerIntegration
    {
        lock(AdmissionLock)
        {
            EnsureConstruction(nameof(AddCandidateIntegration));
            if(typeof(T) == InitialIntegration.GetType())
            {
                InitialIntegration = integration;
            }

            AddIntegration(integration);
        }
    }


    /// <summary>Resolves a family from this view's fixed registry or the owner's current wiring.</summary>
    /// <typeparam name="T">The protocol family's integration type.</typeparam>
    /// <exception cref="InvalidOperationException">The named family has not been registered.</exception>
    public T GetIntegration<T>() where T : ServerIntegration
    {
        EndpointServer wiring = Volatile.Read(ref publishedWiring) ?? this;
        if(wiring.Integrations.TryGetValue(typeof(T), out ServerIntegration? integration))
        {

            return (T)integration;
        }

        throw new InvalidOperationException($"EndpointServer requires AddIntegration<{typeof(T).Name}> in its construction or alteration candidate.");
    }


    /// <summary>
    /// Checks the complete current composition for fail-fast hosting. Admission requires this
    /// explicit check or a successful alteration; dispatch performs no lazy validation.
    /// </summary>
    /// <exception cref="InvalidOperationException">Required wiring is absent or incoherent, or an alteration window owns admission.</exception>
    /// <exception cref="ObjectDisposedException">This server or its serving owner has been disposed.</exception>
    public void Validate()
    {
        lock(WiringOwner.AdmissionLock)
        {
            ValidateOwnedView();
        }
    }


    /// <summary>Validates this view while the serving owner excludes disposal.</summary>
    private void ValidateOwnedView()
    {
        lock(AdmissionLock)
        {
            ObjectDisposedException.ThrowIf(IsDisposed || (Owner?.IsDisposed ?? false), this);
            if(IsAltering || (Owner?.IsAltering ?? false))
            {
                throw new InvalidOperationException("EndpointServer.Validate cannot run during RequestAlterationAsync.");
            }

            HasValidatedWiring = false;
            EndpointServer wiring = Volatile.Read(ref publishedWiring) ?? this;
            wiring.ValidateComposition(() => HasValidatedWiring = true);
        }
    }


    /// <summary>Validates the primary/family relationship, nested groups and configuration policy.</summary>
    /// <param name="onValidated">Updates the serving owner while all composition locks remain held.</param>
    private void ValidateComposition(Action? onValidated = null)
    {
        WiringComponent.WithComponentLocks([InitialIntegration, .. Integrations.Values], () =>
        {
            if(TimeProvider is null)
            {
                throw new InvalidOperationException("EndpointServer requires TimeProvider.");
            }

            InitialIntegration.Attach(this, InvalidateValidation);
            InitialIntegration.Validate();
            if(InitialIntegration.GetType() != typeof(ServerIntegration)
                && (!Integrations.TryGetValue(InitialIntegration.GetType(), out ServerIntegration? family)
                    || !ReferenceEquals(InitialIntegration, family)))
            {
                throw new InvalidOperationException("EndpointServer.Integration must be the same instance registered by AddIntegration for its primary protocol family.");
            }

            foreach(ServerIntegration integration in Integrations.Values)
            {
                integration.Attach(this, InvalidateValidation);
                if(!ReferenceEquals(integration, InitialIntegration))
                {
                    integration.ValidateFamily(InitialIntegration);
                }
            }

            if(InitialConfiguration is null || InitialConfiguration.EndpointBuilders is null
                || (InitialConfiguration.EndpointBuilders.Count == 0 && !InitialConfiguration.IsMaintenanceMode))
            {
                throw new InvalidOperationException("EndpointServer requires ServerConfiguration.EndpointBuilders or explicit IsMaintenanceMode.");
            }

            InitialConfiguration.ValidatePolicy();

            HasValidatedWiring = true;
            onValidated?.Invoke();
        });
    }


    /// <summary>Replaces construction configuration; serving changes require an alteration candidate.</summary>
    /// <param name="configuration">The immutable replacement.</param>
    public void ApplyConfiguration(ServerConfiguration configuration)
    {
        lock(AdmissionLock)
        {
            ArgumentNullException.ThrowIfNull(configuration);
            EnsureConstruction(nameof(ApplyConfiguration));
            InitialConfiguration = configuration;
        }
    }


    /// <summary>
    /// Queues a candidate alteration and returns immediately. Requests already admitted complete
    /// before the callback runs; queued callbacks run in order and publish only after validation.
    /// </summary>
    /// <remarks>
    /// An observer inside a dispatch may request an alteration and return without awaiting it.
    /// Awaiting that task inside the dispatch would wait for its own admission lease to drain.
    /// Completion permits the host to retire replaced resources once retained flows cease using them.
    /// Storage replacement requires the host's migration or forwarding step for persisted flows.
    /// </remarks>
    /// <param name="alter">Edits the independent candidate; coupled changes belong in one callback.</param>
    /// <param name="cancellationToken">
    /// Cancels this request before its window opens with no admission effect. Once a window is open,
    /// cancelling the request that opened it bounds <see cref="ProcessAlterationsAsync"/>'s drain wait
    /// together with <see cref="ServerConfiguration.DrainTimeout"/>; checked again before the callback
    /// and after it returns.
    /// </param>
    /// <returns>Completion of publication, or the named candidate validation or drain-abandonment fault.</returns>
    /// <exception cref="ArgumentNullException">The callback is null; thrown synchronously.</exception>
    /// <exception cref="ObjectDisposedException">The serving owner is disposed; thrown synchronously.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The admission or drain policy is outside its permitted bounds; thrown synchronously.</exception>
    public Task RequestAlterationAsync(Action<AlterationCandidate> alter, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(alter);
        if(Owner is not null)
        {

            return Owner.RequestAlterationAsync(alter, cancellationToken);
        }

        if(cancellationToken.IsCancellationRequested)
        {

            return Task.FromCanceled(cancellationToken);
        }

        TaskCompletionSource completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        lock(AdmissionLock)
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);
            if(cancellationToken.IsCancellationRequested)
            {

                return Task.FromCanceled(cancellationToken);
            }

            Configuration.ValidatePolicy();
            AlterationRequest request = new(alter, completion, cancellationToken);
            if(IsAltering && DrainWait is { IsCompleted: true })
            {
                PendingAlterations.Enqueue(request);
            }
            else
            {
                Alterations.Enqueue(request);
            }

            if(!IsAltering)
            {
                if(OpenWindow())
                {
                    _ = Task.Run(ProcessAlterationsAsync, CancellationToken.None);
                }
            }
        }

        return completion.Task;
    }


    /// <summary>Closes admission and starts a bounded wait before the worker can execute callbacks.</summary>
    /// <remarks>The caller holds AdmissionLock; the first request supplies this window's cancellation token.</remarks>
    /// <returns>Whether an uncancelled request opened a window for the worker.</returns>
    private bool OpenWindow()
    {
        RemoveCancelledRequests(Alterations);
        if(Alterations.Count == 0)
        {

            return false;
        }

        IsAltering = true;
        AdmissionCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        DrainCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        if(InFlightCount == 0)
        {
            DrainCompletion.SetResult();
        }

        DrainWait = DrainCompletion.Task.WaitAsync(Configuration.DrainTimeout, Alterations.Peek().CancellationToken);

        return true;
    }


    /// <summary>Closes the current window once and starts a fresh window for requests outside its membership.</summary>
    /// <returns>Whether another window needs the same worker.</returns>
    private bool AdvanceWindow()
    {
        _ = AdmissionCompletion!.TrySetResult();
        IsAltering = false;
        RemoveCancelledRequests(PendingAlterations);
        while(PendingAlterations.TryDequeue(out AlterationRequest? request))
        {
            Alterations.Enqueue(request);
        }

        if(Alterations.Count == 0)
        {

            return false;
        }

        return OpenWindow();
    }


    /// <summary>Completes cancelled queued requests before a live opener can own admission.</summary>
    /// <param name="requests">The queue protected by admission ownership.</param>
    private static void RemoveCancelledRequests(Queue<AlterationRequest> requests)
    {
        int count = requests.Count;
        for(int index = 0; index < count; ++index)
        {
            AlterationRequest request = requests.Dequeue();
            if(request.CancellationToken.IsCancellationRequested)
            {
                _ = request.Completion.TrySetCanceled(request.CancellationToken);
            }
            else
            {
                requests.Enqueue(request);
            }
        }
    }


    /// <summary>The internal observation of the worker's registered drain wait for bounded host diagnostics.</summary>
    internal Action<Task>? DrainWaitStarted { get; set; }


    /// <summary>The internal terminal-drain observation before admission ownership is reacquired.</summary>
    internal Action? DrainWaitFinished { get; set; }


    /// <summary>Registers the drain continuation before its task is exposed to an observer.</summary>
    private async Task WaitForDrainAsync()
    {
        await DrainWait!.ConfigureAwait(false);
    }


    /// <summary>Drains requests and publishes ordered candidates, containing every worker failure.</summary>
    private async Task ProcessAlterationsAsync()
    {
        AlterationRequest? activeRequest = null;
        try
        {
            while(true)
            {
                Exception? abandonment = null;
                try
                {
                    Task drain = WaitForDrainAsync();
                    DrainWaitStarted?.Invoke(drain);
                    await drain.ConfigureAwait(false);
                }
                catch(TimeoutException)
                {
                    abandonment = new InvalidOperationException(
                        "EndpointServer alteration drain did not complete within ServerConfiguration.DrainTimeout; the live wiring is unchanged and admission has reopened.");
                }
                catch(OperationCanceledException)
                {
                    abandonment = new InvalidOperationException(
                        "EndpointServer abandoned the alteration window because the opening request was cancelled; the live wiring is unchanged and admission has reopened.");
                }

                DrainWaitFinished?.Invoke();
                if(abandonment is not null)
                {
                    bool hasNextWindow = AbandonDrain(abandonment);
                    if(!hasNextWindow)
                    {

                        return;
                    }

                    continue;
                }

                while(true)
                {
                    lock(AdmissionLock)
                    {
                        activeRequest = Alterations.Dequeue();
                    }

                    EndpointServer? candidate = null;
                    Exception? failure = null;
                    bool isCancelled = false;
                    try
                    {
                        activeRequest.CancellationToken.ThrowIfCancellationRequested();
                        ObjectDisposedException.ThrowIf(IsDisposed, this);
                        candidate = CreateView(true);
                        activeRequest.Alter(new AlterationCandidate(candidate));
                        activeRequest.CancellationToken.ThrowIfCancellationRequested();
                        candidate.FreezeComposition();
                        candidate.ValidateComposition();
                        lock(AdmissionLock)
                        {
                            ObjectDisposedException.ThrowIf(IsDisposed, this);
                            EndpointServer source = Volatile.Read(ref publishedWiring) ?? this;
                            source.FreezeComposition();
                            candidate.Owner = this;
                            Volatile.Write(ref publishedWiring, candidate);
                            HasValidatedWiring = true;
                            IsServing = true;
                        }
                    }
                    catch(OperationCanceledException) when(activeRequest.CancellationToken.IsCancellationRequested)
                    {
                        isCancelled = true;
                    }
                    catch(Exception exception)
                    {
                        failure = exception;
                    }
                    finally
                    {
                        candidate?.FreezeComposition();
                        if(IsDisposed)
                        {
                            candidate?.DetachComposition();
                        }
                    }

                    lock(AdmissionLock)
                    {
                        bool isWindowFinished = Alterations.Count == 0;
                        bool hasNextWindow = isWindowFinished && AdvanceWindow();
                        if(isCancelled)
                        {
                            _ = activeRequest.Completion.TrySetCanceled(activeRequest.CancellationToken);
                        }
                        else if(failure is not null)
                        {
                            _ = activeRequest.Completion.TrySetException(failure);
                        }
                        else
                        {
                            _ = activeRequest.Completion.TrySetResult();
                        }

                        activeRequest = null;
                        if(!isWindowFinished)
                        {
                            continue;
                        }

                        if(!hasNextWindow)
                        {

                            return;
                        }
                    }

                    break;
                }
            }
        }
        catch(Exception exception)
        {
            lock(AdmissionLock)
            {
                _ = (activeRequest?.Completion.TrySetException(exception));
                while(Alterations.TryDequeue(out AlterationRequest? request))
                {
                    _ = request.Completion.TrySetException(exception);
                }

                while(PendingAlterations.TryDequeue(out AlterationRequest? pending))
                {
                    _ = pending.Completion.TrySetException(exception);
                }

                IsAltering = false;
                _ = (AdmissionCompletion?.TrySetResult());
            }
        }
    }


    /// <summary>Abandons only the requests belonging to the completed drain wait.</summary>
    /// <remarks>
    /// The wait's exception preserves its actual cause. Each request's own cancelled token takes
    /// precedence over that cause; later arrivals belong to a fresh window and cannot inherit it.
    /// </remarks>
    /// <param name="cause">The named timeout or opening-request cancellation fault.</param>
    /// <returns>Whether a fresh window has pending work.</returns>
    private bool AbandonDrain(Exception cause)
    {
        lock(AdmissionLock)
        {
            while(Alterations.TryDequeue(out AlterationRequest? request))
            {
                if(request.CancellationToken.IsCancellationRequested)
                {
                    _ = request.Completion.TrySetCanceled(request.CancellationToken);
                }
                else
                {
                    _ = request.Completion.TrySetException(cause);
                }
            }

            return AdvanceWindow();
        }
    }


    /// <summary>Copies wiring containers for a candidate, or fixes construction wiring for first admission.</summary>
    /// <param name="isCandidate">Whether to copy the mutable containers.</param>
    private EndpointServer CreateView(bool isCandidate)
    {
        EndpointServer source = Volatile.Read(ref publishedWiring) ?? this;
        Dictionary<ServerIntegration, ServerIntegration> copies = new(ReferenceEqualityComparer.Instance);
        //Preserves alias relationships while copying each integration once.
        ServerIntegration Copy(ServerIntegration integration)
        {
            if(!isCandidate)
            {

                return integration;
            }

            if(!copies.TryGetValue(integration, out ServerIntegration? copy))
            {
                copy = (ServerIntegration)integration.CreateCandidateCopy();
                copies.Add(integration, copy);
            }

            return copy;
        }

        EndpointServer view = null!;
        WiringComponent.WithComponentLocks([source.InitialIntegration, .. source.Integrations.Values], () =>
        {
            view = new()
            {
                Integration = Copy(source.InitialIntegration),
                Configuration = source.InitialConfiguration,
                TimeProvider = TimeProvider,
                ActionExecutor = source.InitialActionExecutor
            };
            foreach(KeyValuePair<Type, ServerIntegration> pair in source.Integrations)
            {
                ServerIntegration integration = Copy(pair.Value);
                view.Integrations.Add(pair.Key, integration);
                integration.Attach(view, view.InvalidateValidation);
            }
        });

        view.Owner = this;
        view.HasValidatedWiring = !isCandidate && HasValidatedWiring;
        lock(AdmissionLock)
        {
            if(IsDisposed)
            {
                view.DetachComposition();
                throw new ObjectDisposedException(nameof(EndpointServer));
            }

            _ = OwnedViews.RemoveAll(reference => !reference.TryGetTarget(out _));
            OwnedViews.Add(new(view));
        }

        return view;
    }


    /// <summary>Freezes all containers while leaving shared application resources host-owned.</summary>
    private void FreezeComposition()
    {
        IsServing = true;
        bool isComplete = false;
        while(!isComplete)
        {
            WiringComponent[] roots = [InitialIntegration, .. AttachedComponents.Keys];
            WiringComponent.WithComponentLocks(roots, () =>
            {
                if(AttachedComponents.Keys.Any(component => !roots.Contains(component)))
                {

                    return;
                }

                foreach(WiringComponent component in roots)
                {
                    component.Freeze();
                }

                isComplete = true;
            });
        }
    }


    /// <summary>Invalidates an editable composition after a setter or registry change.</summary>
    private void InvalidateValidation()
    {
        HasValidatedWiring = false;
    }


    /// <summary>Restricts direct server mutation to construction and candidate composition.</summary>
    /// <param name="member">The edited member named in the fault.</param>
    private void EnsureConstruction(string member)
    {
        ObjectDisposedException.ThrowIf(IsDisposed || (Owner?.IsDisposed ?? false), this);
        if(IsServing || IsAltering)
        {
            throw new InvalidOperationException($"EndpointServer.{member} requires RequestAlterationAsync once the server serves.");
        }

        InvalidateValidation();
    }


    /// <summary>
    /// Acquires validated wiring for any serving entry point, including global registration.
    /// Returns null when the bounded admission wait expires; the caller emits <see cref="AdmissionRefusal"/>.
    /// </summary>
    /// <remarks>The caller must dispose the returned lease after completing its request so queued alterations can drain.</remarks>
    /// <param name="context">The request context that retains the admitted view.</param>
    /// <param name="cancellationToken">Cancels admission without creating an in-flight request.</param>
    public async ValueTask<ServerRequestLease?> AcquireRequestAsync(ExchangeContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        if(Owner is not null)
        {

            return await Owner.AcquireRequestAsync(context, cancellationToken).ConfigureAwait(false);
        }

        lock(AdmissionLock)
        {
            if(!HasValidatedWiring && !IsAltering)
            {
                throw new InvalidOperationException("EndpointServer.Validate or a successful RequestAlterationAsync is required before admission.");
            }
        }

        TimeSpan waitTimeout = Configuration.AdmissionWaitTimeout;

        using CancellationTokenSource timeout = new(waitTimeout);
        using CancellationTokenSource admission = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token, cancellationToken);
        while(true)
        {
            Task wait;
            lock(AdmissionLock)
            {
                ObjectDisposedException.ThrowIf(IsDisposed, this);
                cancellationToken.ThrowIfCancellationRequested();
                if(!IsAltering)
                {
                    if(!HasValidatedWiring)
                    {
                        throw new InvalidOperationException("EndpointServer.Validate or a successful RequestAlterationAsync is required before admission.");
                    }

                    EndpointServer? wiring = Volatile.Read(ref publishedWiring);
                    if(wiring is null)
                    {
                        FreezeComposition();
                        if(!HasValidatedWiring)
                        {
                            throw new InvalidOperationException("EndpointServer.Validate or a successful RequestAlterationAsync is required before admission.");
                        }

                        wiring = CreateView(false);
                        wiring.FreezeComposition();
                        wiring.Owner = this;
                        Volatile.Write(ref publishedWiring, wiring);
                    }

                    ++InFlightCount;
                    context.SetServer(this);
                    context.SetRequestServer(wiring);

                    return new ServerRequestLease(wiring, ReleaseRequest);
                }

                wait = AdmissionCompletion!.Task;
            }

            try
            {
                await wait.WaitAsync(admission.Token).ConfigureAwait(false);
            }
            catch(OperationCanceledException) when(timeout.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {

                return null;
            }
        }
    }


    /// <summary>
    /// The refusal used when admission's bounded hold expires, for every capability alike.
    /// </summary>
    /// <remarks>
    /// HTTP 503 and the one-second Retry-After delay-seconds value follow
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.6.4">RFC 9110 §15.6.4</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-10.2.3">§10.2.3</see>. The body carries
    /// <see cref="ServerErrors.TemporarilyUnavailable"/>; see that member for the scope of its citation.
    /// The description names only the transient condition, not the reconfiguration in progress.
    /// </remarks>
    public static ServerHttpResponse AdmissionRefusal =>
        (ServerHttpResponse.ServerError(ServerErrors.TemporarilyUnavailable, "The server is temporarily unable to accept this request. Retry the request.")
            with
        { StatusCode = 503 }).WithHeader("Retry-After", "1");


    /// <summary>Releases one admitted request and wakes the alteration worker at quiescence.</summary>
    private void ReleaseRequest()
    {
        lock(AdmissionLock)
        {
            --InFlightCount;
            if(InFlightCount == 0 && IsAltering)
            {
                _ = DrainCompletion!.TrySetResult();
            }
        }
    }


    /// <summary>One ordered candidate request and the completion owned by its requester.</summary>
    /// <param name="Alter">The candidate callback.</param>
    /// <param name="CancellationToken">Cancellation before publication.</param>
    /// <param name="Completion">Asynchronously delivered result.</param>
    private sealed record AlterationRequest(Action<AlterationCandidate> Alter, TaskCompletionSource Completion, CancellationToken CancellationToken);


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

        using ServerRequestLease? lease = await AcquireRequestAsync(context, cancellationToken).ConfigureAwait(false);
        if(lease is null)
        {

            return AdmissionRefusal;
        }

        return await lease.Server.DispatchCapturedAsync(request, context, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Executes the pipeline entirely against this request's fixed wiring view.</summary>
    /// <param name="request">The transport envelope.</param>
    /// <param name="context">The exclusively owned request context.</param>
    /// <param name="cancellationToken">Cancellation of request processing.</param>
    private async ValueTask<ServerHttpResponse> DispatchCapturedAsync(IncomingRequest request, ExchangeContext context, CancellationToken cancellationToken)
    {
        using Activity? activity = ServerActivitySource.Source.StartActivity(
            ServerActivityNames.Handle);

        //Place the active host and typed request envelope on the context.
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
                response = await Integration.ResolveMissingRegistrationAsync(
                    tenantId.Value, context, cancellationToken).ConfigureAwait(false);

                _ = (activity?.AddEvent(new ActivityEvent(ServerEventNames.NoMatch,
                    tags: new ActivityTagsCollection
                    {
                        [ServerEventNames.NoMatchCategoryTagName] = NoMatchCategories.NoRegistrationForTenant
                    })));
            }
            else
            {
                context.SetRegistration(registration);

                if(registration.TenantHandle is TenantHandle tenantHandle)
                {
                    _ = (activity?.SetTag(ServerTagNames.TenantHandle, tenantHandle.Value));
                }

                _ = (activity?.SetTag(ServerTagNames.RegistrationId, registration.ClientId));

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

                    _ = (activity?.SetTag(ServerTagNames.FlowKind, matched.Endpoint.Kind.Name));
                    _ = (activity?.SetTag(ServerTagNames.HttpMethod, matched.Endpoint.HttpMethod));
                    _ = (activity?.SetTag(ServerTagNames.StartsNewFlow, matched.Endpoint.StartsNewFlow));
                }

                //Inspection stage 2 of 4 — match decision.
                await Integration.InspectAsync!(
                    new MatchedStage(matched?.Endpoint, matched?.Payload),
                    context, cancellationToken).ConfigureAwait(false);

                if(matched is null)
                {
                    string noMatchCategory = chain.Count > 0
                        ? NoMatchCategories.MatcherDeclined
                        : chain.CapabilityFilteredCandidateNames.Count > 0
                            ? NoMatchCategories.CapabilityFiltered
                            : chain.UnresolvedUriCandidateNames.Count > 0
                                ? NoMatchCategories.EndpointNameUnresolved
                                : NoMatchCategories.NoCandidateForPathAndMethod;

                    string[] declinedCandidateNames = new string[chain.Count];
                    for(int i = 0; i < chain.Count; i++)
                    {
                        declinedCandidateNames[i] = chain[i].Name;
                    }

                    _ = (activity?.AddEvent(new ActivityEvent(ServerEventNames.NoMatch,
                        tags: new ActivityTagsCollection
                        {
                            [ServerEventNames.NoMatchCategoryTagName] = noMatchCategory,
                            [ServerEventNames.NoMatchCandidateCountTagName] =
                                chain.Count.ToString(CultureInfo.InvariantCulture),
                            [ServerEventNames.NoMatchCapabilityFilteredTagName] =
                                string.Join(' ', chain.CapabilityFilteredCandidateNames),
                            [ServerEventNames.NoMatchEndpointNameUnresolvedTagName] =
                                string.Join(' ', chain.UnresolvedUriCandidateNames),
                            [ServerEventNames.NoMatchDeclinedTagName] =
                                string.Join(' ', declinedCandidateNames)
                        })));

                    response = ServerHttpResponse.NotFound();
                }
                else
                {
                    ServerHttpResponse? materializationFailure = null;
                    if(Integration.MaterializeRegistrationAsync is not null)
                    {
                        RegistrationMaterialization materialization = await Integration.MaterializeRegistrationAsync(
                            registration, context, cancellationToken).ConfigureAwait(false);

                        materializationFailure = materialization.Failure;
                        if(materializationFailure is null && materialization.Registration is not null)
                        {
                            registration = materialization.Registration;
                            context.SetRegistration(registration);
                        }
                    }

                    response = materializationFailure ?? await HandleCoreAsync(
                        matched.Endpoint, request.Fields, context, activity, cancellationToken)
                        .ConfigureAwait(false);
                }
            }
        }

        //Inspection stage 4 of 4 — fired immediately before the response returns.
        try
        {
            await Integration.InspectAsync!(
                new OutgoingResponseStage(response), context, cancellationToken)
                .ConfigureAwait(false);
        }
        catch(Exception exception)
        {
            _ = activity?.AddException(exception);
        }


        _ = (activity?.SetTag(
            ServerTagNames.StatusCode,
            response.StatusCode.ToString(CultureInfo.InvariantCulture)));

        if(response.ErrorCode is not null)
        {
            _ = (activity?.SetTag(ServerTagNames.ErrorCode, response.ErrorCode));
        }

        return response;
    }


    /// <summary>Runs a matched endpoint using the wiring retained by its admission lease.</summary>
    private async ValueTask<ServerHttpResponse> HandleCoreAsync(
        ServerEndpoint endpoint,
        RequestFields fields,
        ExchangeContext context,
        Activity? activity,
        CancellationToken cancellationToken)
    {
        ValueTask<ServerHttpResponse?> RunBeforeCorrelationStepAsync() =>
            endpoint.BeforeCorrelationAsync is not null
                ? endpoint.BeforeCorrelationAsync(endpoint, fields, context, cancellationToken)
                : ValueTask.FromResult<ServerHttpResponse?>(null);

        //1. The endpoint's own pre-correlation step. A stateless endpoint and a new-flow endpoint
        //carry no correlation handle, so their step runs here, before anything else. A
        //continuing-flow endpoint's step runs after the handle-presence refusal below and before
        //the handle is resolved or its state loaded — see the second call site in the
        //continuing-flow branch (still step 1 of this same numbered list).
        if(endpoint.Kind is StatelessFlowKind || endpoint.StartsNewFlow)
        {
            ServerHttpResponse? beforeCorrelationRefusal = await RunBeforeCorrelationStepAsync().ConfigureAwait(false);

            if(beforeCorrelationRefusal is not null)
            {
                return beforeCorrelationRefusal;
            }
        }

        //2. Stateless endpoints short-circuit here: no PDA, no persistence.
        if(endpoint.Kind is StatelessFlowKind)
        {
            FlowState statelessSentinel = CreateStatelessSentinel(
                endpoint.Kind, TimeProvider);

            (_, ServerHttpResponse? statelessEarlyExit) =
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

            _ = (activity?.AddEvent(new ActivityEvent(ServerEventNames.FlowCreated)));
        }
        else
        {
            string externalHandle = endpoint.ExtractCorrelationKey is not null
                ? endpoint.ExtractCorrelationKey(string.Empty, fields, context) ?? string.Empty
                : context.CorrelationKey ?? string.Empty;

            //RFC 6749 §3.1: "Parameters sent without a value MUST be treated as if they were omitted from the request."
            //Only null/empty is omitted. Any other value, including whitespace, is judged by
            //the endpoint's own correlation resolution.
            if(string.IsNullOrEmpty(externalHandle))
            {

                return ServerHttpResponse.BadRequest(
                    ServerErrors.InvalidRequest,
                    endpoint.MissingCorrelationKeyErrorDescription ?? "Cannot determine correlation key.");
            }

            //1. (continuing-flow position) The same pre-correlation step as above, run here for a
            //continuing-flow endpoint — after its own handle-presence refusal, before the handle
            //is resolved or its state loaded.
            ServerHttpResponse? continuingBeforeCorrelationRefusal = await RunBeforeCorrelationStepAsync().ConfigureAwait(false);

            if(continuingBeforeCorrelationRefusal is not null)
            {
                return continuingBeforeCorrelationRefusal;
            }

            if(Integration.ResolveCorrelationKeyAsync is not null)
            {
                string? resolved = await Integration.ResolveCorrelationKeyAsync(
                    context.TenantId!.Value, endpoint.Kind, externalHandle, context, cancellationToken)
                    .ConfigureAwait(false);

                if(resolved is null)
                {
                    _ = (activity?.AddEvent(new ActivityEvent(ServerEventNames.CorrelationNotFound)));
                    _ = (activity?.SetTag(ServerTagNames.CorrelationResolved, false));

                    return ServerHttpResponse.BadRequest(
                        endpoint.HandleNotFoundError ?? ServerErrors.InvalidRequest,
                        endpoint.HandleNotFoundErrorDescription ?? "Flow not found or expired.");
                }

                flowId = resolved;
                _ = (activity?.AddEvent(new ActivityEvent(ServerEventNames.CorrelationResolved)));
                _ = (activity?.SetTag(ServerTagNames.CorrelationResolved, true));
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
                    endpoint.HandleNotFoundError ?? ServerErrors.InvalidRequest,
                    endpoint.HandleNotFoundErrorDescription ?? "Flow not found or expired.");
            }

            DateTimeOffset now = TimeProvider.GetUtcNow();
            if(savedState.ExpiresAt <= now)
            {

                return ServerHttpResponse.BadRequest(
                    endpoint.HandleNotFoundError ?? ServerErrors.InvalidRequest,
                    endpoint.HandleNotFoundErrorDescription ?? "Flow not found or expired.");
            }

            currentState = savedState;
            currentStepCount = savedStepCount;
        }

        //4. Stamp the request time and the loaded step count once, so a handler that must
        //claim the flow before an irreversible effect (see ClaimServerFlowStateDelegate) can
        //read the exact step this request observed without HandleCoreAsync's local
        //currentStepCount being threaded through BuildInputDelegate's signature.
        context.SetVerifiedAt(TimeProvider.GetUtcNow());
        context.SetFlowStepCount(currentStepCount);

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

        _ = (activity?.SetTag(ServerTagNames.FlowState, newState.GetType().Name));
        _ = (activity?.SetTag(ServerTagNames.FlowStepCount, newStepCount));
        _ = (activity?.AddEvent(new ActivityEvent(ServerEventNames.StateTransition)));

        //7. Build the response.
        ServerHttpResponse response = endpoint.BuildResponse(
            newState, newState.Kind.Name, context);

        //8. Persist under the internal flowId.
        await Integration.SaveFlowStateAsync!(
            context.TenantId!.Value, flowId, newState, newStepCount, context, cancellationToken)
            .ConfigureAwait(false);

        return response;
    }


    /// <summary>Creates the unpersisted state required by a stateless endpoint's input signature.</summary>
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


    /// <summary>Tracks an attachment so disposal also releases replaced construction containers.</summary>
    /// <param name="component">The component holding this server's invalidator.</param>
    internal void TrackAttachment(WiringComponent component)
    {
        _ = AttachedComponents.TryAdd(component, 0);
    }


    /// <summary>Releases this view's component subscriptions without disposing application resources.</summary>
    private void DetachComposition()
    {
        bool isComplete = false;
        while(!isComplete)
        {
            WiringComponent[] roots = [.. AttachedComponents.Keys];
            WiringComponent.WithComponentLocks(roots, () =>
            {
                if(AttachedComponents.Keys.Any(component => !roots.Contains(component)))
                {

                    return;
                }

                foreach(WiringComponent component in roots)
                {
                    component.Detach(this);
                }

                AttachedComponents.Clear();
                isComplete = true;
            });
        }
    }


    /// <summary>Releases construction and published-view ownership; application resources remain host-owned.</summary>
    /// <remarks>Disposing a request view disposes its serving owner. Disposing a request lease only releases that lease.</remarks>
    public void Dispose()
    {
        if(Owner is not null)
        {
            Owner.Dispose();

            return;
        }

        lock(AdmissionLock)
        {
            IsDisposed = true;
            DetachComposition();
            foreach(WeakReference<EndpointServer> reference in OwnedViews)
            {
                if(reference.TryGetTarget(out EndpointServer? view))
                {
                    view.DetachComposition();
                }
            }

            OwnedViews.Clear();
        }
    }
}
