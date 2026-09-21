using System.Runtime.CompilerServices;

namespace Verifiable.Server;

/// <summary>
/// A mutable construction or candidate component that becomes read-only when admitted wiring uses it.
/// </summary>
/// <remarks>
/// Serving changes belong to <see cref="EndpointServer.RequestAlterationAsync"/>. Copies share
/// application delegate targets; the application owns their synchronization and resource lifetime.
/// </remarks>
public abstract class WiringComponent
{
    /// <summary>The sequence supplying stable lock order; this field is an Interlocked target.</summary>
    private static long nextAcquisitionKey;


    /// <summary>The stable order of this component's lock, independent of composition membership.</summary>
    private long AcquisitionKey { get; set; } = Interlocked.Increment(ref nextAcquisitionKey);


    /// <summary>Serializes a complete setter with publication freezing.</summary>
    /// <remarks>Operations needing several component locks collect the full graph first and acquire locks in ascending acquisition-key order. Nested assignments use WithComponentLocks with both the receiver and the supplied graph.</remarks>
    protected object MutationLock { get; private set; } = new();


    /// <summary>Whether this component belongs to published wiring.</summary>
    private bool IsFrozen { get; set; }


    /// <summary>Whether nested assignments must adopt independent candidate containers.</summary>
    private bool IsCandidateCopy { get; set; }


    /// <summary>
    /// The distinct construction owners' validation invalidators, keyed by owner identity.
    /// </summary>
    /// <remarks>
    /// A dictionary rather than a single callback so a component shared by construction across more
    /// than one <see cref="EndpointServer"/> invalidates every owner's validation on an edit, not only
    /// the owner that last called <see cref="Attach"/>; re-attaching the same owner replaces its entry
    /// instead of accumulating one, since a server re-attaches on every <see cref="EndpointServer.Validate"/> call.
    /// </remarks>
    private Dictionary<object, Action> InvalidateOwners { get; set; } = new(ReferenceEqualityComparer.Instance);


    /// <summary>The composition that consumed this source's one adoption, independent of attachment lifetime.</summary>
    private object? AdoptionOwner { get; set; }


    /// <summary>Whether structural validation succeeded after this component's last edit.</summary>
    public bool IsValidated
    {
        get => Volatile.Read(ref field);
        protected set => Volatile.Write(ref field, value);
    }


    /// <summary>Refuses a serving edit and invalidates validation before a construction or candidate edit.</summary>
    /// <param name="member">The edited member, included in the named configuration fault.</param>
    protected void EnsureMutable([CallerMemberName] string member = "")
    {
        if(IsFrozen)
        {
            throw new InvalidOperationException(
                $"{GetType().Name}.{member} requires EndpointServer.RequestAlterationAsync once the server serves.");
        }

        IsValidated = false;
        foreach(Action invalidate in InvalidateOwners.Values)
        {
            invalidate();
        }
    }


    /// <summary>Copies this component's wiring and detaches the copy from its serving owner.</summary>
    /// <remarks>Derived components copy their own mutable containers here and expose nested components through <see cref="Children"/>.</remarks>
    protected virtual WiringComponent CloneCore()
    {
        WiringComponent copy = (WiringComponent)MemberwiseClone();
        copy.MutationLock = new();
        copy.AcquisitionKey = Interlocked.Increment(ref nextAcquisitionKey);
        copy.AdoptionOwner = null;
        copy.IsFrozen = false;
        copy.IsCandidateCopy = false;
        copy.IsValidated = false;
        copy.InvalidateOwners = new(ReferenceEqualityComparer.Instance);

        return copy;
    }


    /// <summary>Copies a nested wiring container while retaining its application resources.</summary>
    /// <typeparam name="T">The nested component type.</typeparam>
    /// <param name="component">The source container.</param>
    protected static T CopyComponent<T>(T component) where T : WiringComponent
    {
        ArgumentNullException.ThrowIfNull(component);

        return (T)component.CreateCandidateCopy();
    }


    /// <summary>Adopts a nested assignment and attaches its validation invalidation to this component's owners.</summary>
    /// <remarks>Candidate assignments copy containers, including components attached to their own composition, and refuse components attached to another composition. A fresh source permits one adoption; the copy shares application resources and event subscriptions with that source.</remarks>
    /// <typeparam name="T">The assigned component type.</typeparam>
    /// <param name="component">The supplied container, or null for candidate validation to reject when required.</param>
    /// <param name="member">The setter named in an ownership fault.</param>
    protected T? AdoptComponent<T>(T? component, [CallerMemberName] string member = "") where T : WiringComponent
    {
        if(component is null)
        {

            return null;
        }

        T adopted = IsCandidateCopy
            ? (T)component.CreateAdoptedCopy(InvalidateOwners.Keys, $"{GetType().Name}.{member}")
            : component;
        foreach(KeyValuePair<object, Action> owner in InvalidateOwners)
        {
            adopted.Attach(owner.Key, () =>
            {
                IsValidated = false;
                owner.Value();
            });
        }

        return adopted;
    }


    /// <summary>Copies an adopted graph atomically with ownership checks on every nested container.</summary>
    /// <param name="allowedOwners">Owners belonging to the candidate receiving the copy.</param>
    /// <param name="member">The member named when another server owns a supplied container.</param>
    internal WiringComponent CreateAdoptedCopy(IEnumerable<object> allowedOwners, string member)
    {
        WiringComponent? copy = null;
        WithMutationLock(() =>
        {
            EnsureAdoptable(allowedOwners, member);
            copy = CloneCore();
            copy.IsCandidateCopy = true;
            MarkAdopted(ResolveOwner(allowedOwners.First()));
        });

        return copy!;
    }


    /// <summary>Checks the complete supplied graph while its mutation locks are held.</summary>
    /// <param name="allowedOwners">The receiving candidate's owner identities.</param>
    /// <param name="member">The member named in the ownership fault.</param>
    private void EnsureAdoptable(IEnumerable<object> allowedOwners, string member)
    {
        if(AdoptionOwner is not null || InvalidateOwners.Keys.Any(owner => !allowedOwners.Any(allowed => ReferenceEquals(ResolveOwner(owner), ResolveOwner(allowed)))))
        {
            throw new InvalidOperationException($"{member} requires a component that has not been adopted and is not attached to another EndpointServer.");
        }

        foreach(WiringComponent child in Children)
        {
            child.EnsureAdoptable(allowedOwners, member);
        }
    }


    /// <summary>Consumes each supplied source's adoption while its complete graph remains locked.</summary>
    /// <param name="owner">The stable receiving composition identity.</param>
    private void MarkAdopted(object owner)
    {
        AdoptionOwner = owner;
        foreach(WiringComponent child in Children)
        {
            child.MarkAdopted(owner);
        }
    }


    /// <summary>Resolves candidate and admitted views to their stable serving identity.</summary>
    /// <param name="owner">The component attachment identity.</param>
    private static object ResolveOwner(object owner)
    {

        return owner is EndpointServer server ? server.WiringOwner : owner;
    }


    /// <summary>Enumerates mutable child containers that share this component's lifecycle.</summary>
    /// <remarks>Derived components include every nested wiring component so validation invalidation and freezing reach it.</remarks>
    protected virtual IEnumerable<WiringComponent> Children => [];


    /// <summary>Attaches construction validation invalidation to this component and its children.</summary>
    /// <remarks>A component shared by construction becomes frozen for every owner when any owner serves or publishes. Each owner can then alter its own copied composition through RequestAlterationAsync.</remarks>
    /// <param name="owner">The identity re-attaching replaces rather than accumulates an entry for.</param>
    /// <param name="invalidate">The owning server's invalidator.</param>
    internal void Attach(object owner, Action invalidate)
    {
        WithMutationLock(() =>
        {
            EnsureAttachable(owner);
            AttachCore(owner, invalidate);
        });
    }


    /// <summary>Checks the complete locked graph before any ownership entry is written.</summary>
    /// <param name="owner">The receiving composition identity.</param>
    private void EnsureAttachable(object owner)
    {
        if(AdoptionOwner is not null && !ReferenceEquals(AdoptionOwner, ResolveOwner(owner)))
        {
            throw new InvalidOperationException("WiringComponent.Attach requires a component not adopted by another EndpointServer.");
        }

        foreach(WiringComponent child in Children)
        {
            child.EnsureAttachable(owner);
        }
    }


    /// <summary>Attaches a locked graph without acquiring locks in traversal order.</summary>
    /// <param name="owner">The receiving view identity.</param>
    /// <param name="invalidate">The owning composition's validation invalidator.</param>
    private void AttachCore(object owner, Action invalidate)
    {
        InvalidateOwners[owner] = invalidate;
        if(owner is EndpointServer server)
        {
            server.TrackAttachment(this);
        }

        foreach(WiringComponent child in Children)
        {
            child.AttachCore(owner, () =>
            {
                IsValidated = false;
                invalidate();
            });
        }
    }


    /// <summary>Releases a disposed server's ownership without disposing application resources.</summary>
    /// <param name="owner">The server whose invalidation subscription is removed.</param>
    internal void Detach(object owner)
    {
        WithMutationLock(() => DetachCore(owner));
    }


    /// <summary>Detaches a graph while its globally ordered locks remain held.</summary>
    /// <param name="owner">The identity to remove from every child.</param>
    private void DetachCore(object owner)
    {
        _ = InvalidateOwners.Remove(owner);
        foreach(WiringComponent child in Children)
        {
            child.DetachCore(owner);
        }
    }


    /// <summary>Prevents further edits to a published or discarded candidate and its children.</summary>
    internal void Freeze()
    {
        WithMutationLock(FreezeCore);
    }


    /// <summary>Freezes a graph under the locks acquired before traversal.</summary>
    private void FreezeCore()
    {
        IsFrozen = true;
        foreach(WiringComponent child in Children)
        {
            child.FreezeCore();
        }
    }


    /// <summary>Runs an operation with this component and all children locked in stable order.</summary>
    /// <param name="operation">The operation requiring a coherent graph.</param>
    internal void WithMutationLock(Action operation)
    {
        WithComponentLocks([this], operation);
    }


    /// <summary>Collects complete graphs and acquires their distinct locks in ascending stable order.</summary>
    /// <remarks>Collection holds one lock at a time. A child introduced before acquisition causes a retry before the operation runs. Reentrant calls only revisit held locks or acquire freshly constructed components.</remarks>
    /// <param name="roots">The receivers and supplied components participating in the operation.</param>
    /// <param name="operation">The operation run once a complete graph is locked.</param>
    protected internal static void WithComponentLocks(IEnumerable<WiringComponent?> roots, Action operation)
    {
        ArgumentNullException.ThrowIfNull(roots);
        ArgumentNullException.ThrowIfNull(operation);

        WiringComponent[] starting = [.. roots.OfType<WiringComponent>()];
        while(true)
        {
            HashSet<WiringComponent> components = new(ReferenceEqualityComparer.Instance);
            Queue<WiringComponent> pending = new(starting);
            while(pending.TryDequeue(out WiringComponent? component))
            {
                if(components.Add(component))
                {
                    lock(component.MutationLock)
                    {
                        foreach(WiringComponent child in component.Children)
                        {
                            pending.Enqueue(child);
                        }
                    }
                }
            }

            WiringComponent[] ordered = [.. components.OrderBy(component => component.AcquisitionKey)];
            int acquired = 0;
            try
            {
                foreach(WiringComponent component in ordered)
                {
                    Monitor.Enter(component.MutationLock);
                    ++acquired;
                }

                bool isComplete = ordered.All(component => component.Children.All(components.Contains));
                if(!isComplete)
                {
                    continue;
                }

                operation();

                return;
            }
            finally
            {
                for(int index = acquired - 1; index >= 0; --index)
                {
                    Monitor.Exit(ordered[index].MutationLock);
                }
            }
        }
    }


    /// <summary>Creates the independent candidate container used by the server's alteration operation.</summary>
    internal WiringComponent CreateCandidateCopy()
    {
        WiringComponent? copy = null;
        WithMutationLock(() =>
        {
            copy = CloneCore();
            copy.IsCandidateCopy = true;
        });

        return copy!;
    }
}
