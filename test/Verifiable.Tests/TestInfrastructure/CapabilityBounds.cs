using System.Collections.Immutable;
using Verifiable.OAuth.Server;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The two ways a capability a registration does not serve the request under reaches a reader: an application's
/// materialization that answers the registration with the capability added, which the dispatcher's bound withholds,
/// and an application's capability resolution that withholds a capability the registration allows. A row that proves
/// a reader reads the bounded set runs both forms and compares each answer with that of a registration that never
/// held the capability.
/// </summary>
internal static class CapabilityBounds
{
    /// <summary>The form in which the application's materialization adds the capability.</summary>
    public static string MaterializationAdds { get; } = "materializationAdds";

    /// <summary>The form in which the application's capability resolution withholds the capability.</summary>
    public static string ResolutionWithholds { get; } = "resolutionWithholds";


    /// <summary>
    /// The capabilities the loaded registration allows in <paramref name="form"/>: <paramref name="neverHeld"/> when
    /// the materialization adds <paramref name="capability"/>, and <paramref name="neverHeld"/> with
    /// <paramref name="capability"/> when the capability resolution withholds it.
    /// </summary>
    /// <param name="form"><see cref="MaterializationAdds"/> or <see cref="ResolutionWithholds"/>.</param>
    /// <param name="neverHeld">The capabilities of the registration that never held <paramref name="capability"/>.</param>
    /// <param name="capability">The capability the bound withholds.</param>
    /// <returns>The capabilities to register.</returns>
    public static ImmutableHashSet<CapabilityIdentifier> Registered(
        string form, ImmutableHashSet<CapabilityIdentifier> neverHeld, CapabilityIdentifier capability) =>
        form switch
        {
            _ when string.Equals(form, MaterializationAdds, StringComparison.Ordinal) => neverHeld,
            _ when string.Equals(form, ResolutionWithholds, StringComparison.Ordinal) => neverHeld.Add(capability),
            _ => throw new ArgumentOutOfRangeException(nameof(form), form, "Unknown form.")
        };


    /// <summary>
    /// Wires <paramref name="form"/> on an integration: the materialization that answers the client registration
    /// with <paramref name="capability"/> added and every other member kept, or the capability resolution that
    /// answers a registration's own capabilities without <paramref name="capability"/>.
    /// </summary>
    /// <param name="form"><see cref="MaterializationAdds"/> or <see cref="ResolutionWithholds"/>.</param>
    /// <param name="capability">The capability the bound withholds.</param>
    /// <returns>The wiring, for <see cref="Verifiable.Tests.OAuth.TestHostShell.AlterAsync"/>.</returns>
    public static Action<AuthorizationServerIntegration> Wire(string form, CapabilityIdentifier capability) =>
        form switch
        {
            _ when string.Equals(form, MaterializationAdds, StringComparison.Ordinal) =>
                candidateIntegration => candidateIntegration.MaterializeRegistrationAsync = MaterializationAdding(capability),
            _ when string.Equals(form, ResolutionWithholds, StringComparison.Ordinal) =>
                candidateIntegration => candidateIntegration.ResolveCapabilitiesAsync = ResolutionWithholding(capability),
            _ => throw new ArgumentOutOfRangeException(nameof(form), form, "Unknown form.")
        };


    /// <summary>
    /// A materialization that answers the client registration it is handed with <paramref name="capability"/> added
    /// to its capabilities, every other member kept.
    /// </summary>
    /// <param name="capability">The capability the materialized registration adds.</param>
    /// <returns>The materialization seam.</returns>
    public static MaterializeRegistrationDelegate MaterializationAdding(CapabilityIdentifier capability) =>
        (registration, _, _) => ValueTask.FromResult(new RegistrationMaterialization
        {
            Registration = ((ClientRecord)registration) with
            {
                AllowedCapabilities = ((ClientRecord)registration).AllowedCapabilities.Add(capability)
            }
        });


    /// <summary>
    /// A capability resolution that answers the capabilities a registration allows without
    /// <paramref name="capability"/>.
    /// </summary>
    /// <param name="capability">The capability the resolution withholds.</param>
    /// <returns>The capability-resolution seam.</returns>
    public static ResolveCapabilitiesDelegate ResolutionWithholding(CapabilityIdentifier capability) =>
        (registration, _, _) => ValueTask.FromResult<IReadOnlySet<CapabilityIdentifier>>(
            registration.AllowedCapabilities.Where(allowed => allowed != capability).ToHashSet());
}
