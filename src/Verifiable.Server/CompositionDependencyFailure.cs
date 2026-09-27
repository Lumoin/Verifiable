using System.Diagnostics;

namespace Verifiable.Server;

/// <summary>
/// One declared capability paired with one wiring dependency it lacks: the typed unit of a
/// capability-scoped validation refusal.
/// </summary>
/// <remarks>
/// A composition that declares its capabilities through
/// <see cref="ServerConfiguration.DeclaredCapabilities"/> is validated only for those capabilities'
/// dependencies. <see cref="ServerIntegration.ValidateDeclaredCapabilities"/> returns one failure per
/// missing dependency of each declared capability, and <see cref="EndpointServer"/> refuses the
/// composition with a <see cref="CompositionDependencyException"/> carrying every failure together, so
/// a host sees each capability that cannot be served and the member that would let it be served.
/// </remarks>
[DebuggerDisplay("{Capability} requires {Dependency}")]
public sealed record CompositionDependencyFailure
{
    /// <summary>
    /// Creates a failure naming a declared capability and the dependency it lacks.
    /// </summary>
    /// <param name="capability">The declared capability that cannot be served.</param>
    /// <param name="dependency">The wiring member the capability needs and the composition lacks.</param>
    /// <exception cref="ArgumentException">
    /// The capability or the dependency is the default value, which names nothing.
    /// </exception>
    public CompositionDependencyFailure(CapabilityIdentifier capability, CompositionDependency dependency)
    {
        if(capability.Urn is null)
        {
            throw new ArgumentException("A composition dependency failure names a declared capability.", nameof(capability));
        }

        if(dependency.Member is null)
        {
            throw new ArgumentException("A composition dependency failure names a dependency.", nameof(dependency));
        }

        Capability = capability;
        Dependency = dependency;
    }


    /// <summary>The declared capability whose dependency is missing.</summary>
    public CapabilityIdentifier Capability { get; }


    /// <summary>The wiring member the capability needs and the composition lacks.</summary>
    public CompositionDependency Dependency { get; }


    /// <summary>Returns the failure as the capability URN followed by the dependency it requires.</summary>
    /// <returns>The text <c>{urn} requires {member path}</c>.</returns>
    public override string ToString()
    {

        return $"{Capability.Urn} requires {Dependency}";
    }
}
