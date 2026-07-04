namespace Verifiable.WebFinger;

/// <summary>
/// A diagnostic describing why a WebFinger resolution did not produce a JSON Resource Descriptor.
/// Carries a stable <see cref="Code"/> for programmatic branching and a human-readable
/// <see cref="Description"/>. Standard conditions are exposed by <see cref="WebFingerResolutionErrors"/>.
/// </summary>
public sealed record WebFingerResolutionError
{
    /// <summary>A stable, machine-comparable error code.</summary>
    public required string Code { get; init; }

    /// <summary>A human-readable description of the condition. Not for display to untrusted callers verbatim.</summary>
    public required string Description { get; init; }
}
