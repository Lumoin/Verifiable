using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Server;

/// <summary>
/// Refuses a composition whose declared capabilities lack wiring they need, carrying every missing
/// dependency as a typed <see cref="CompositionDependencyFailure"/>.
/// </summary>
/// <remarks>
/// <para>
/// A composition that declares its capabilities through
/// <see cref="ServerConfiguration.DeclaredCapabilities"/> is validated only for those capabilities'
/// dependencies. <see cref="EndpointServer.Validate"/> and
/// <see cref="EndpointServer.RequestAlterationAsync"/> raise this exception after every other
/// structural check has passed, naming each declared capability with the dependency it lacks, ordered
/// by capability URN and then by dependency path so the report is the same on every run.
/// </para>
/// <para>
/// Deriving from <see cref="InvalidOperationException"/> keeps the named configuration fault
/// <see href="../../documents/AuthorizationServerDesign.md#41-live-configuration">Live configuration §4.1</see>
/// states: "The named `InvalidOperationException` identifies missing or incoherent wiring." A host
/// already catching that type for missing or incoherent wiring receives this refusal through the same
/// handler. A composition that declares nothing never raises it.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1032:Implement standard exception constructors", Justification = "This exception always carries the dependency failures that refused the composition; the parameterless and message-only constructors would violate that invariant.")]
public sealed class CompositionDependencyException : InvalidOperationException
{
    /// <summary>
    /// Creates the refusal from the failures in the order they are reported.
    /// </summary>
    /// <param name="failures">The declared capabilities and the dependencies they lack; at least one.</param>
    /// <exception cref="ArgumentNullException"><paramref name="failures"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="failures"/> is empty or contains <see langword="null"/>.</exception>
    public CompositionDependencyException(IEnumerable<CompositionDependencyFailure> failures)
        : this(Snapshot(failures))
    {
    }


    /// <summary>Carries the validated snapshot into the message and the <see cref="Failures"/> list.</summary>
    /// <param name="failures">The validated, non-empty snapshot.</param>
    private CompositionDependencyException(ImmutableArray<CompositionDependencyFailure> failures)
        : base(ComposeMessage(failures))
    {
        Failures = failures;
    }


    /// <summary>
    /// The declared capabilities and the dependencies they lack, in reported order; never empty.
    /// </summary>
    public ImmutableArray<CompositionDependencyFailure> Failures { get; }


    /// <summary>Copies the failures once so the message and <see cref="Failures"/> describe the same list.</summary>
    /// <param name="failures">The caller's failures.</param>
    /// <returns>An immutable, non-empty snapshot without null members.</returns>
    private static ImmutableArray<CompositionDependencyFailure> Snapshot(IEnumerable<CompositionDependencyFailure> failures)
    {
        ArgumentNullException.ThrowIfNull(failures);
        ImmutableArray<CompositionDependencyFailure> snapshot = [.. failures];
        if(snapshot.IsEmpty)
        {
            throw new ArgumentException("A composition dependency refusal carries at least one failure.", nameof(failures));
        }

        if(snapshot.Contains(null!))
        {
            throw new ArgumentException("A composition dependency refusal carries no null failure.", nameof(failures));
        }

        return snapshot;
    }


    /// <summary>Lists every failure as <c>{urn} requires {member path}</c> in the given order.</summary>
    /// <param name="failures">The validated snapshot.</param>
    /// <returns>The exception message.</returns>
    private static string ComposeMessage(ImmutableArray<CompositionDependencyFailure> failures)
    {

        return $"ServerConfiguration.DeclaredCapabilities names capabilities whose dependencies are missing: {string.Join(", ", failures)}.";
    }
}
