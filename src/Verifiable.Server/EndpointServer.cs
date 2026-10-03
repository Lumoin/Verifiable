using System.Collections.Concurrent;
using System.Collections.Immutable;
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
    /// <exception cref="InvalidOperationException">
    /// Required wiring is absent or incoherent, or an alteration window owns admission. A declared
    /// capability lacking a dependency raises the derived <see cref="CompositionDependencyException"/>.
    /// </exception>
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
    /// <remarks>
    /// Without <see cref="ServerConfiguration.DeclaredCapabilities"/> every family runs its full check.
    /// With a declaration a member that is the default <see cref="CapabilityIdentifier"/> is refused with
    /// the named <see cref="InvalidOperationException"/> before any family runs, every family runs
    /// <see cref="ServerIntegration.ValidateDeclaredCapabilities"/>, the host-level dependencies the
    /// families describe through <see cref="ServerIntegration.DescribeServerDependencies"/> are checked
    /// against this composition's own wiring, an empty declaration needs explicit maintenance mode, and
    /// the declared capabilities' missing dependencies are refused together, ordered by capability URN
    /// and then dependency path, after every other check has passed.
    /// </remarks>
    /// <param name="onValidated">Updates the serving owner while all composition locks remain held.</param>
    /// <exception cref="CompositionDependencyException">A declared capability lacks a dependency.</exception>
    private void ValidateComposition(Action? onValidated = null)
    {
        WiringComponent.WithComponentLocks([InitialIntegration, .. Integrations.Values], () =>
        {
            if(TimeProvider is null)
            {
                throw new InvalidOperationException("EndpointServer requires TimeProvider.");
            }

            ImmutableHashSet<CapabilityIdentifier>? declaredCapabilities = InitialConfiguration?.DeclaredCapabilities;
            List<CompositionDependencyFailure> failures = [];
            InitialIntegration.Attach(this, InvalidateValidation);

            //A default identifier names no capability, so it is incoherent wiring rather than a
            //capability a dependency failure could name; it is refused before any family reports one.
            if(declaredCapabilities is not null && declaredCapabilities.Any(capability => capability.Urn is null))
            {
                throw new InvalidOperationException("EndpointServer requires ServerConfiguration.DeclaredCapabilities to name only created capabilities.");
            }

            if(declaredCapabilities is null)
            {
                InitialIntegration.Validate();
            }
            else
            {
                failures.AddRange(InitialIntegration.ValidateDeclaredCapabilities(InitialIntegration, declaredCapabilities));
            }

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
                    if(declaredCapabilities is null)
                    {
                        integration.ValidateFamily(InitialIntegration);
                    }
                    else
                    {
                        failures.AddRange(integration.ValidateDeclaredCapabilities(InitialIntegration, declaredCapabilities));
                    }
                }
            }

            if(declaredCapabilities is not null)
            {
                failures.AddRange(CollectMissingServerDependencies(declaredCapabilities));
            }

            if(InitialConfiguration is null || InitialConfiguration.EndpointBuilders is null
                || (InitialConfiguration.EndpointBuilders.Count == 0 && !InitialConfiguration.IsMaintenanceMode))
            {
                throw new InvalidOperationException("EndpointServer requires ServerConfiguration.EndpointBuilders or explicit IsMaintenanceMode.");
            }

            if(declaredCapabilities is { Count: 0 } && !InitialConfiguration.IsMaintenanceMode)
            {
                throw new InvalidOperationException("EndpointServer requires ServerConfiguration.DeclaredCapabilities to name a capability or explicit IsMaintenanceMode.");
            }

            InitialConfiguration.ValidatePolicy();
            if(failures.Count > 0)
            {
                throw new CompositionDependencyException(failures
                    .OrderBy(failure => failure.Capability.Urn, StringComparer.Ordinal)
                    .ThenBy(failure => failure.Dependency.ToString(), StringComparer.Ordinal));
            }

            HasValidatedWiring = true;
            onValidated?.Invoke();
        });
    }


    /// <summary>
    /// Collects the host-level dependencies every family describes for the declared capabilities through
    /// <see cref="ServerIntegration.DescribeServerDependencies"/> and returns those this composition's own
    /// wiring lacks, each named once.
    /// </summary>
    /// <param name="declaredCapabilities">The capabilities the composition declares it serves.</param>
    /// <returns>One failure per declared capability and missing host-level dependency; empty when none is missing.</returns>
    private IEnumerable<CompositionDependencyFailure> CollectMissingServerDependencies(ImmutableHashSet<CapabilityIdentifier> declaredCapabilities)
    {

        return Integrations.Values.Prepend(InitialIntegration)
            .Distinct<ServerIntegration>(ReferenceEqualityComparer.Instance)
            .SelectMany(family => declaredCapabilities.SelectMany(capability => family.DescribeServerDependencies(capability)
                .Where(dependency => !IsServerDependencyWired(dependency))
                .Select(dependency => new CompositionDependencyFailure(capability, dependency))))
            .Distinct();
    }


    /// <summary>
    /// Answers whether this composition wires a host-level dependency a family describes. A dependency
    /// naming no member this host carries is never wired, so the refusal names it rather than passing it.
    /// </summary>
    /// <param name="dependency">A host-level dependency a family describes.</param>
    /// <returns>Whether this composition's own member is present.</returns>
    private bool IsServerDependencyWired(CompositionDependency dependency)
    {

        return dependency switch
        {
            _ when dependency == CompositionDependency.ServerActionExecutor => InitialActionExecutor is not null,
            _ => false
        };
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
    /// <returns>
    /// Completion of publication, or the named candidate validation or drain-abandonment fault; a
    /// candidate whose declared capability lacks a dependency faults with <see cref="CompositionDependencyException"/>.
    /// </returns>
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
        { StatusCode = 503 }).WithHeader(WellKnownHttpHeaderNames.RetryAfter, "1");


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

                //2.5 and 2.6 Resolve per-request policy and the issuer URI for downstream emitters
                //and place them on the context. The issuer the request arrived with and the entries
                //the policy resolution wrote are kept so a materialized registration resolves its
                //policy and issuer from the same starting point.
                Uri? requestIssuer = context.Issuer;
                PolicyEntries loadedPolicy = await ResolvePolicyAndIssuerAsync(
                    registration, requestIssuer, earlierPolicy: null, context, cancellationToken).ConfigureAwait(false);

                //3. Build the registration's active endpoint chain and walk it.
                EndpointChain chain = await EndpointChain.BuildForRequestAsync(
                    registration, context, cancellationToken).ConfigureAwait(false);
                context.SetEndpointChain(chain);

                MatchedEndpoint? matched = await chain.MatchAsync(
                    request.Fields, context, cancellationToken).ConfigureAwait(false);

                if(matched is not null)
                {
                    RecordMatch(matched, context, activity);
                }

                //Inspection stage 2 of 4 — match decision.
                await Integration.InspectAsync!(
                    new MatchedStage(matched?.Endpoint, matched?.Payload),
                    context, cancellationToken).ConfigureAwait(false);

                if(matched is null)
                {
                    response = NoMatchResponse(chain, activity);
                }
                else
                {
                    ServerHttpResponse? materializationFailure = null;
                    IRegistrationRecord? materialized = null;
                    if(Integration.MaterializeRegistrationAsync is not null)
                    {
                        RegistrationMaterialization materialization = await Integration.MaterializeRegistrationAsync(
                            registration, context, cancellationToken).ConfigureAwait(false);

                        materializationFailure = materialization.Failure;
                        if(materializationFailure is null && materialization.Registration is not null)
                        {
                            materialized = materialization.Registration;
                            context.SetRegistration(materialized);
                        }
                    }

                    response = materializationFailure
                        ?? (materialized is null || ReferenceEquals(materialized, registration)
                            ? await HandleCoreAsync(
                                matched.Endpoint, request.Fields, context, activity, cancellationToken)
                                .ConfigureAwait(false)
                            : await JudgeMaterializedAsync(
                                registration, materialized, requestIssuer, loadedPolicy, chain, matched, request.Fields, context, activity, cancellationToken)
                                .ConfigureAwait(false));
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


    /// <summary>
    /// Resolves the per-request policy and the issuer URI for <paramref name="registration"/> and places them on
    /// <paramref name="context"/>: once for the loaded registration, and again for a registration the application's
    /// materialization answers in its place, so the request is served under the values of the registration the
    /// endpoint runs with.
    /// </summary>
    /// <remarks>
    /// A policy axis a registration's profile does not set is absent from the context and reads its strict default,
    /// unless the request arrived with the entry. When the application's
    /// <see cref="ServerIntegration.MaterializeRegistrationAsync"/> is wired, the values of the entries present
    /// before the loaded registration's policy resolution are recorded with the entries that resolution wrote. Before
    /// the materialized registration's policy is resolved, every entry the loaded registration's resolution wrote is
    /// returned to the value the request arrived with, or removed when the request arrived without it, an entry
    /// written under such a name between the two resolutions included, so the
    /// materialized registration's resolution starts from the request's arriving state, as its issuer does: an axis
    /// its profile does not set reads the value the request arrived with or its strict default, never the loaded
    /// registration's value.
    /// </remarks>
    /// <param name="registration">The registration the policy and the issuer are resolved for.</param>
    /// <param name="requestIssuer">
    /// The issuer the context carried as the request arrived, or <see langword="null"/> for none. Every resolution
    /// starts from it, and it stays when no issuer seam is wired.
    /// </param>
    /// <param name="earlierPolicy">
    /// The entries an earlier registration's policy resolution found and wrote on <paramref name="context"/> for this
    /// request, returned to their arriving values before this resolution; <see langword="null"/> for the loaded
    /// registration.
    /// </param>
    /// <param name="context">The per-request context the values are placed on.</param>
    /// <param name="cancellationToken">Cancellation of request processing.</param>
    /// <returns>
    /// The entries <paramref name="context"/> held before this policy resolution and the entries it wrote, when the
    /// application's <see cref="ServerIntegration.MaterializeRegistrationAsync"/> is wired, so a materialized
    /// registration's resolution can start from the arriving state and be compared with this one;
    /// <see cref="PolicyEntries.None"/> when it is not wired.
    /// </returns>
    private async ValueTask<PolicyEntries> ResolvePolicyAndIssuerAsync(
        IRegistrationRecord registration,
        Uri? requestIssuer,
        PolicyEntries? earlierPolicy,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        //The issuer one registration resolved is never the starting point of another's resolution.
        if(!Equals(context.Issuer, requestIssuer))
        {
            if(requestIssuer is not null)
            {
                context.SetIssuer(requestIssuer);
            }
            else
            {
                _ = context.Remove(ServerContextKeys.IssuerKey);
            }
        }

        //The policy one registration resolved is never the starting point of another's resolution: every entry it
        //wrote returns to the value the request arrived with.
        if(earlierPolicy is not null)
        {
            foreach(string entryName in earlierPolicy.Written.Keys)
            {
                if(earlierPolicy.Before.TryGetValue(entryName, out object? arrivingValue))
                {
                    context[entryName] = arrivingValue;
                }
                else
                {
                    _ = context.Remove(entryName);
                }
            }
        }

        //The entries present before the resolution are recorded only when a materialization can follow.
        Dictionary<string, object>? entriesBefore = Integration.MaterializeRegistrationAsync is not null
            ? new Dictionary<string, object>(context, StringComparer.Ordinal)
            : null;

        await Integration.ResolvePolicyAsync!(
            registration, context, cancellationToken).ConfigureAwait(false);

        PolicyEntries policy = entriesBefore is null
            ? PolicyEntries.None
            : new PolicyEntries
            {
                Before = entriesBefore,
                Written = WrittenEntries(entriesBefore, context)
            };

        Uri? issuer = Integration.ResolveIssuerAsync is not null
            ? await Integration.ResolveIssuerAsync(
                registration, context, cancellationToken).ConfigureAwait(false)
            : requestIssuer;

        if(issuer is not null)
        {
            context.SetIssuer(issuer);
        }

        return policy;
    }


    /// <summary>
    /// The entries a policy resolution wrote on <paramref name="context"/>: every entry it added or set to a value
    /// other than the one it held before, with the value it holds after, and every entry it removed, with
    /// <see langword="null"/>. An entry set to the value it already held is not among them, since the context reads
    /// the same either way.
    /// </summary>
    /// <param name="entriesBefore">The entries <paramref name="context"/> held before the resolution.</param>
    /// <param name="context">The context after the resolution.</param>
    /// <returns>The entries written, by name.</returns>
    private static Dictionary<string, object?> WrittenEntries(
        Dictionary<string, object> entriesBefore, ExchangeContext context)
    {
        Dictionary<string, object?> written = new(StringComparer.Ordinal);
        foreach(KeyValuePair<string, object> entry in context)
        {
            if(!entriesBefore.TryGetValue(entry.Key, out object? valueBefore) || !Equals(valueBefore, entry.Value))
            {
                written[entry.Key] = entry.Value;
            }
        }

        foreach(string entryName in entriesBefore.Keys)
        {
            if(!context.ContainsKey(entryName))
            {
                written[entryName] = null;
            }
        }

        return written;
    }


    /// <summary>
    /// Whether two registrations' policy resolutions for one request leave any policy entry at a different value: an
    /// entry either resolution wrote is read as that resolution left it, and an entry it did not write as the request
    /// arrived with it. The endpoint builders read the per-request policy as they build their candidates, so a
    /// different policy builds a different chain.
    /// </summary>
    /// <param name="loadedPolicy">The entries the loaded registration's policy resolution found and wrote.</param>
    /// <param name="materializedPolicy">The entries the materialized registration's policy resolution found and wrote.</param>
    /// <returns><see langword="true"/> when an entry differs between the two resolutions.</returns>
    private static bool IsPolicyChanged(PolicyEntries loadedPolicy, PolicyEntries materializedPolicy)
    {
        foreach(string entryName in loadedPolicy.Written.Keys.Concat(materializedPolicy.Written.Keys))
        {
            object? loadedValue = loadedPolicy.Written.TryGetValue(entryName, out object? writtenByLoaded)
                ? writtenByLoaded
                : loadedPolicy.Before.GetValueOrDefault(entryName);
            object? materializedValue = materializedPolicy.Written.TryGetValue(entryName, out object? writtenByMaterialized)
                ? writtenByMaterialized
                : materializedPolicy.Before.GetValueOrDefault(entryName);
            if(!Equals(loadedValue, materializedValue))
            {

                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// The policy entries one registration's policy resolution found on the request's context and the entries it
    /// wrote, recorded so the resolution for a registration the application's materialization answers in place of the
    /// loaded one starts from the request's arriving state and is compared with the loaded registration's.
    /// </summary>
    private sealed class PolicyEntries
    {
        /// <summary>
        /// The entries recorded for no resolution, when the application's
        /// <see cref="ServerIntegration.MaterializeRegistrationAsync"/> is not wired and no second resolution follows.
        /// </summary>
        internal static PolicyEntries None { get; } = new()
        {
            Before = new Dictionary<string, object>(StringComparer.Ordinal),
            Written = new Dictionary<string, object?>(StringComparer.Ordinal)
        };

        /// <summary>The entries the context held before the resolution, by name.</summary>
        internal required Dictionary<string, object> Before { get; init; }

        /// <summary>
        /// The entries the resolution wrote, by name, with the value each holds after it, or <see langword="null"/>
        /// for an entry it removed.
        /// </summary>
        internal required Dictionary<string, object?> Written { get; init; }
    }


    /// <summary>
    /// Judges a matched request by the registration the application's
    /// <see cref="ServerIntegration.MaterializeRegistrationAsync"/> answered in place of the loaded one, so one
    /// registration is judged per request: policy and issuer are resolved for the materialized registration, and when
    /// it does not allow every capability the loaded registration allows or its policy differs from the loaded
    /// registration's, the endpoint chain is built again for it and the request matched again.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A materialization narrows the endpoint chain and the resolved capabilities and never widens them. Each
    /// capability the materialized registration adds is recorded as
    /// <see cref="ServerEventNames.MaterializedCapabilityDropped"/>. When the materialization removes no capability and
    /// its policy resolution leaves every policy entry at the value the loaded registration's resolution left it, the
    /// chain built for the loaded registration and its resolved capabilities are kept. A kept chain is the loaded
    /// registration's in every input: its capability resolution, its endpoint addresses and whatever else its builders
    /// read of the registration. It is kept only when the materialized registration allows every loaded capability
    /// under an unchanged policy. Otherwise the chain is built again with
    /// <see cref="EndpointChain.BuildBoundedForRequestAsync"/>: its resolved capabilities are held to the capabilities
    /// resolved for the loaded registration that both registrations allow, and its endpoints to the endpoints of the
    /// chain built for the loaded registration, each identified by its name, HTTP method and flow kind together, so an
    /// endpoint that chain lacks is dropped and recorded among
    /// <see cref="EndpointChain.CapabilityFilteredCandidateNames"/>. A candidate that a builder's gate admits for a
    /// capability the materialized registration adds, a gate that reads two capabilities of the registration while its
    /// candidate carries one of them, is therefore dropped unless the loaded chain holds an endpoint of that same name,
    /// HTTP method and flow kind. The bound does not tell apart a builder that yields, under one name, HTTP method and
    /// flow kind, a candidate whose handler depends on a capability beyond the one it carries: the bound compares what
    /// a chain records of an endpoint, and a builder is handed the registration as the materialization answered it. An
    /// endpoint that reads the registration's own capabilities as it runs reads the materialized ones.
    /// </para>
    /// <para>
    /// A policy change alone builds the chain again, since the endpoint builders read the per-request policy as they
    /// build their candidates: the authorization endpoint's candidate takes the pushed-authorization requirement into
    /// its claim of a request that names no reference and into the error it answers an unresolved reference with, so a
    /// chain kept from the loaded registration would answer under the loaded registration's policy.
    /// </para>
    /// <para>
    /// A capability the materialization removes is answered as one the registration never held: the chain built again
    /// has no candidate for it, so the request is answered as a request no candidate matches or by the candidate that
    /// refuses what the registration is not allowed. Two cases do not hold, both whenever the chain is built again,
    /// for a capability removed or for a policy change alone. First, a token-serving grant the materialization adds
    /// and the server serves answers the dispatcher's <c>404</c> where a registration that never held it answers
    /// <c>unauthorized_client</c>: the token endpoint's module registers the grant from the record's own capabilities,
    /// so its grant-type refusal declines the grant, while the bound drops the grant's own candidate. Second, when the
    /// added capability precedes every kept one in the order the token endpoint takes its grant-type refusal's
    /// capability from, the refusal itself carries the added capability and is dropped, so every token request no kept
    /// grant candidate owns answers the <c>404</c>: a missing or blank <c>grant_type</c>, a grant the server serves
    /// that the materialized registration does not hold, the removed one included, and a grant the server does not
    /// serve, where a registration that never held the added capability answers <c>invalid_request</c>,
    /// <c>unauthorized_client</c> and <c>unsupported_grant_type</c>. The cause of both is the token endpoint's module,
    /// which reads the record's own capabilities for its registered grants and for the capability its refusal
    /// carries.
    /// </para>
    /// <para>
    /// Whenever the chain is built again, the match-decision inspection (<see cref="MatchedStage"/>) runs again for
    /// the decision that is executed, the endpoint matched in the chain built again or none, before the endpoint runs
    /// or the no-match answer is sent, whether or not that decision equals the first; a request's last announced
    /// decision is the one executed. A request no endpoint of the chain built again matches carries neither the first
    /// match's payload and capability on the context nor its flow kind, method and starts-flow tags on the dispatch
    /// activity.
    /// </para>
    /// <para>
    /// The endpoint builders and handlers read the registration as their own family's record. A materialized record of
    /// another type than the loaded one is a fault of the application's wiring whatever its capabilities: no endpoint
    /// runs over it, the request is answered <c>500</c> <c>server_error</c> with the description the library answers a
    /// fault of the server's own wiring with, and the fault is recorded on the dispatch activity.
    /// </para>
    /// </remarks>
    /// <param name="loaded">The registration the application's load seam answered.</param>
    /// <param name="materialized">The registration the materialization answered in its place.</param>
    /// <param name="requestIssuer">The issuer the context carried as the request arrived, or <see langword="null"/>.</param>
    /// <param name="loadedPolicy">
    /// The entries the policy resolution of <paramref name="loaded"/> found on the context and the entries it wrote.
    /// </param>
    /// <param name="loadedChain">The endpoint chain built for <paramref name="loaded"/>.</param>
    /// <param name="matched">The endpoint matched in <paramref name="loadedChain"/>.</param>
    /// <param name="fields">The request fields the chain is matched against.</param>
    /// <param name="context">The exclusively owned request context.</param>
    /// <param name="activity">The dispatch activity, or <see langword="null"/> when none is recorded.</param>
    /// <param name="cancellationToken">Cancellation of request processing.</param>
    /// <returns>The response for the request.</returns>
    private async ValueTask<ServerHttpResponse> JudgeMaterializedAsync(
        IRegistrationRecord loaded,
        IRegistrationRecord materialized,
        Uri? requestIssuer,
        PolicyEntries loadedPolicy,
        EndpointChain loadedChain,
        MatchedEndpoint matched,
        RequestFields fields,
        ExchangeContext context,
        Activity? activity,
        CancellationToken cancellationToken)
    {
        foreach(CapabilityIdentifier capability in materialized.AllowedCapabilities)
        {
            if(!loaded.AllowedCapabilities.Contains(capability))
            {
                _ = (activity?.AddEvent(new ActivityEvent(ServerEventNames.MaterializedCapabilityDropped,
                    tags: new ActivityTagsCollection
                    {
                        [ServerEventNames.MaterializedCapabilityTagName] = capability.Urn
                    })));
            }
        }

        if(!loaded.GetType().IsInstanceOfType(materialized))
        {
            _ = activity?.AddException(new InvalidOperationException(
                "The materialized registration is a record of another type than the loaded registration, "
                + "so no endpoint can run over it."));

            return ServerHttpResponse.ServerError(ServerErrors.ServerError, ServerNotReadyDescription);
        }

        PolicyEntries materializedPolicy = await ResolvePolicyAndIssuerAsync(
            materialized, requestIssuer, loadedPolicy, context, cancellationToken).ConfigureAwait(false);

        if(!IsPolicyChanged(loadedPolicy, materializedPolicy)
            && materialized.AllowedCapabilities.IsSupersetOf(loaded.AllowedCapabilities))
        {

            return await HandleCoreAsync(
                matched.Endpoint, fields, context, activity, cancellationToken).ConfigureAwait(false);
        }

        IReadOnlySet<CapabilityIdentifier> loadedResolved =
            context.ResolvedCapabilities ?? ImmutableHashSet<CapabilityIdentifier>.Empty;
        HashSet<CapabilityIdentifier> upperBound = [.. loadedResolved.Where(capability =>
            loaded.AllowedCapabilities.Contains(capability) && materialized.AllowedCapabilities.Contains(capability))];

        EndpointChain chain = await EndpointChain.BuildBoundedForRequestAsync(
            materialized, upperBound, loadedChain, context, cancellationToken).ConfigureAwait(false);
        context.SetEndpointChain(chain);

        MatchedEndpoint? rematched = await chain.MatchAsync(
            fields, context, cancellationToken).ConfigureAwait(false);
        if(rematched is null)
        {
            ClearMatch(context, activity);
        }
        else
        {
            RecordMatch(rematched, context, activity);
        }

        //Inspection stage 2 of 4 again: the match decision that is executed, announced after every rebuild.
        await Integration.InspectAsync!(
            new MatchedStage(rematched?.Endpoint, rematched?.Payload),
            context, cancellationToken).ConfigureAwait(false);

        return rematched is null
            ? NoMatchResponse(chain, activity)
            : await HandleCoreAsync(
                rematched.Endpoint, fields, context, activity, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Places a matched endpoint's payload and capability on the context and tags the dispatch activity with the
    /// endpoint's flow kind, method and whether it starts a flow. Called for the match in the chain built for the
    /// loaded registration and again for the match in a chain built for a materialized registration.
    /// </summary>
    /// <param name="matched">The matched endpoint and its payload.</param>
    /// <param name="context">The per-request context.</param>
    /// <param name="activity">The dispatch activity, or <see langword="null"/> when none is recorded.</param>
    private static void RecordMatch(MatchedEndpoint matched, ExchangeContext context, Activity? activity)
    {
        context.SetMatchPayload(matched.Payload);
        context.SetCapability(matched.Endpoint.Capability);

        _ = (activity?.SetTag(ServerTagNames.FlowKind, matched.Endpoint.Kind.Name));
        _ = (activity?.SetTag(ServerTagNames.HttpMethod, matched.Endpoint.HttpMethod));
        _ = (activity?.SetTag(ServerTagNames.StartsNewFlow, matched.Endpoint.StartsNewFlow));
    }


    /// <summary>
    /// Removes the match payload and the capability <see cref="RecordMatch"/> placed on the context and the flow kind,
    /// method and starts-flow tags it placed on the dispatch activity. Called when the chain built for a materialized
    /// registration matches no endpoint, so the outgoing inspection and the trace see a request no candidate matched.
    /// </summary>
    /// <param name="context">The per-request context.</param>
    /// <param name="activity">The dispatch activity, or <see langword="null"/> when none is recorded.</param>
    private static void ClearMatch(ExchangeContext context, Activity? activity)
    {
        _ = context.Remove(ServerContextKeys.MatchPayloadKey);
        _ = context.Remove(ServerContextKeys.CapabilityKey);

        _ = (activity?.SetTag(ServerTagNames.FlowKind, null));
        _ = (activity?.SetTag(ServerTagNames.HttpMethod, null));
        _ = (activity?.SetTag(ServerTagNames.StartsNewFlow, null));
    }


    /// <summary>
    /// Answers a request no candidate of <paramref name="chain"/> matched: <c>404</c> with
    /// <see cref="ServerHttpResponse.NotFound()"/>'s empty shape, and a <see cref="ServerEventNames.NoMatch"/> event on
    /// the dispatch activity naming why, from the chain's own record of the candidates it filtered, could not resolve
    /// or walked. The one answer for a request the chain built for the loaded registration does not match and for one
    /// the chain built for a materialized registration does not match.
    /// </summary>
    /// <param name="chain">The chain the request was walked through.</param>
    /// <param name="activity">The dispatch activity, or <see langword="null"/> when none is recorded.</param>
    /// <returns>The <c>404</c> response.</returns>
    private static ServerHttpResponse NoMatchResponse(EndpointChain chain, Activity? activity)
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

        return ServerHttpResponse.NotFound();
    }


    /// <summary>
    /// The <c>error_description</c> the dispatcher answers beside <see cref="ServerErrors.ServerError"/> when the
    /// application's materialization answers a record of another type than the loaded registration: the fault is the
    /// server's wiring, not the request. The same text as the description the library answers a fault of the server's
    /// own wiring with; it names no seam, configuration or internal cause.
    /// </summary>
    private static string ServerNotReadyDescription { get; } = "The server is not ready to serve this request.";


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

            //RFC 6749 §3.1: "Parameters sent without a value MUST be treated as if they were omitted from
            //the request." Only null/empty is omitted and answers the endpoint's missing-parameter
            //refusal below. Any other value, including whitespace, is present and is judged further
            //down: a whitespace-only value never resolves and is refused immediately, and every other
            //value is carried to the correlation resolver and the flow-state store.
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

            //A present handle carrying only whitespace is judged, not omitted (RFC 6749 §3.1 treats
            //only the empty value as omitted), and it can never identify a live flow. Refusing it here
            //— before any resolver or store call, and never by letting it reach SetFlowId's own
            //validation — keeps this refusal a Result-shaped outcome whether or not a correlation
            //resolver is wired.
            if(string.IsNullOrWhiteSpace(externalHandle))
            {
                _ = (activity?.AddEvent(new ActivityEvent(ServerEventNames.CorrelationNotFound)));
                _ = (activity?.SetTag(ServerTagNames.CorrelationResolved, false));

                return UnresolvedHandleRefusal(endpoint);
            }

            bool isHandleResolved;
            if(Integration.ResolveCorrelationKeyAsync is not null)
            {
                string? resolved = await Integration.ResolveCorrelationKeyAsync(
                    context.TenantId!.Value, endpoint.Kind, externalHandle, context, cancellationToken)
                    .ConfigureAwait(false);

                if(string.IsNullOrWhiteSpace(resolved))
                {
                    _ = (activity?.AddEvent(new ActivityEvent(ServerEventNames.CorrelationNotFound)));
                    _ = (activity?.SetTag(ServerTagNames.CorrelationResolved, false));

                    return UnresolvedHandleRefusal(endpoint);
                }

                flowId = resolved;
                isHandleResolved = true;
                _ = (activity?.AddEvent(new ActivityEvent(ServerEventNames.CorrelationResolved)));
                _ = (activity?.SetTag(ServerTagNames.CorrelationResolved, true));
            }
            else
            {
                flowId = externalHandle;
                isHandleResolved = false;
            }

            context.SetFlowId(flowId);

            (FlowState? savedState, int savedStepCount) =
                await Integration.LoadFlowStateAsync!(
                    context.TenantId!.Value, flowId, context, cancellationToken).ConfigureAwait(false);

            if(savedState is null)
            {

                return isHandleResolved ? HandleNotFoundRefusal(endpoint) : UnresolvedHandleRefusal(endpoint);
            }

            DateTimeOffset now = TimeProvider.GetUtcNow();
            if(savedState.ExpiresAt <= now)
            {

                return HandleNotFoundRefusal(endpoint);
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


    /// <summary>
    /// The <c>error_description</c> a correlation-handle refusal falls back to when the matched endpoint
    /// sets neither <see cref="ServerEndpoint.UnresolvedHandleErrorDescription"/> nor
    /// <see cref="ServerEndpoint.HandleNotFoundErrorDescription"/>. Both <see cref="UnresolvedHandleRefusal"/>
    /// and <see cref="HandleNotFoundRefusal"/> end their fallback chain at this same text, so a policy that
    /// sets neither description answers byte-identically whether the handle never resolved or resolved and
    /// became unusable.
    /// </summary>
    private static string DefaultCorrelationHandleErrorDescription { get; } =
        "Flow not found or expired.";


    /// <summary>
    /// Builds the refusal for a correlation handle that never resolved to a live flow at all — a
    /// whitespace-only value, one the correlation resolver answered with <see langword="null"/> or a
    /// blank value, or one answered by no resolver at all whose load then finds no record. Chooses
    /// <see cref="ServerEndpoint.UnresolvedHandleError"/> when the endpoint set one, then
    /// <see cref="ServerEndpoint.HandleNotFoundError"/>, then the host-generic vocabulary; the paired
    /// description falls back through the same chain, ending at
    /// <see cref="DefaultCorrelationHandleErrorDescription"/>.
    /// </summary>
    /// <param name="endpoint">The matched endpoint whose refusal vocabulary this refusal reads.</param>
    /// <returns>A <c>400 Bad Request</c> response carrying the resolved error and description.</returns>
    private static ServerHttpResponse UnresolvedHandleRefusal(ServerEndpoint endpoint) =>
        ServerHttpResponse.BadRequest(
            endpoint.UnresolvedHandleError ?? endpoint.HandleNotFoundError ?? ServerErrors.InvalidRequest,
            endpoint.UnresolvedHandleErrorDescription
                ?? endpoint.HandleNotFoundErrorDescription
                ?? DefaultCorrelationHandleErrorDescription);


    /// <summary>
    /// Builds the refusal for a correlation handle that resolved but is no longer usable: expired,
    /// already consumed, or missing at load after a resolver found it. Chooses
    /// <see cref="ServerEndpoint.HandleNotFoundError"/> when the endpoint set one, then the host-generic
    /// vocabulary; the paired description falls back the same way, ending at
    /// <see cref="DefaultCorrelationHandleErrorDescription"/>.
    /// </summary>
    /// <param name="endpoint">The matched endpoint whose refusal vocabulary this refusal reads.</param>
    /// <returns>A <c>400 Bad Request</c> response carrying the resolved error and description.</returns>
    private static ServerHttpResponse HandleNotFoundRefusal(ServerEndpoint endpoint) =>
        ServerHttpResponse.BadRequest(
            endpoint.HandleNotFoundError ?? ServerErrors.InvalidRequest,
            endpoint.HandleNotFoundErrorDescription ?? DefaultCorrelationHandleErrorDescription);


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
