namespace Verifiable.Server;

/// <summary>
/// The independent wiring composition supplied to one queued server alteration.
/// Related seams, family containers, action bindings and configuration publish together after validation.
/// </summary>
public sealed class AlterationCandidate
{
    /// <summary>The editable composition owned by this candidate.</summary>
    private EndpointServer Composition { get; }


    /// <summary>Wraps the server's detached wiring copy for the duration of its callback.</summary>
    /// <param name="composition">The unpublished wiring copy.</param>
    internal AlterationCandidate(EndpointServer composition)
    {
        Composition = composition;
    }


    /// <summary>The editable primary integration; its family registry entry refers to the same copy.</summary>
    public ServerIntegration Integration => Composition.Integration;


    /// <summary>The immutable configuration replaced together with this candidate's integration seams.</summary>
    public ServerConfiguration Configuration
    {
        get => Composition.Configuration;
        set => Composition.ApplyConfiguration(value);
    }


    /// <summary>The action bridge used by each subsequent admitted flow.</summary>
    public FlowActionExecutorDelegate? ActionExecutor
    {
        get => Composition.ActionExecutor;
        set => Composition.ActionExecutor = value;
    }


    /// <summary>Resolves an editable family integration from the candidate's independent registry.</summary>
    /// <typeparam name="T">The protocol family type.</typeparam>
    public T Family<T>() where T : ServerIntegration
    {

        return Composition.GetIntegration<T>();
    }


    /// <summary>Registers a candidate family, replacing a matching primary family together with its registry entry.</summary>
    /// <remarks>
    /// Adopts an independent copy of <paramref name="integration"/> rather than the supplied
    /// reference itself, so a candidate that is later discarded cannot leave <paramref name="integration"/>
    /// frozen or re-owned by this composition's validation invalidation. Refuses an
    /// <paramref name="integration"/> that already belongs to another composition
    /// or contains a nested component owned there: copying its nested containers
    /// would carry that other composition's shared application resources, including its
    /// registration-event subscriber list, by reference into this one.
    /// A source can be adopted by only one composition; another composition receives a named ownership fault.
    /// A fresh adopted integration carries its registration-event subject with its copy, so a
    /// subscription made before adoption receives this server's registration events after publication.
    /// Registering under the primary integration's concrete type replaces the primary and its family
    /// registry entry together; other keys register secondary families subject to validation.
    /// </remarks>
    /// <typeparam name="T">The protocol family type.</typeparam>
    /// <param name="integration">The source family integration; the candidate registers its own copy.</param>
    /// <exception cref="InvalidOperationException">
    /// <paramref name="integration"/> is already attached to another <see cref="EndpointServer"/>.
    /// </exception>
    public void AddIntegration<T>(T integration) where T : ServerIntegration
    {
        ArgumentNullException.ThrowIfNull(integration);
        Composition.AddCandidateIntegration((T)integration.CreateAdoptedCopy([Composition], "AlterationCandidate.AddIntegration"));
    }
}
