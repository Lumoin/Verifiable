namespace Verifiable.OAuth.Server;

/// <summary>
/// Provides human-readable names for <see cref="PolicyProfile"/> values.
/// </summary>
/// <remarks>
/// Mirrors the <see cref="ServerCapabilityNames"/> /
/// <see cref="Verifiable.Cryptography.Context.EntropySourceNames"/> companion
/// pattern. Names are returned for built-in profiles by name lookup;
/// application-registered codes return a generic <c>Custom (code)</c> form
/// since the library does not own their human-readable label.
/// </remarks>
public static class PolicyProfileNames
{
    /// <summary>Gets the name for the specified profile.</summary>
    public static string GetName(PolicyProfile profile) => GetName(profile.Code);


    /// <summary>Gets the name for the specified profile code.</summary>
    public static string GetName(int code) => code switch
    {
        var c when c == PolicyProfile.Strict.Code => nameof(PolicyProfile.Strict),
        var c when c == PolicyProfile.Haip.Code => nameof(PolicyProfile.Haip),
        var c when c == PolicyProfile.Rfc6749.Code => nameof(PolicyProfile.Rfc6749),
        _ => $"Custom ({code})"
    };
}
