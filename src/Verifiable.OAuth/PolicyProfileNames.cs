namespace Verifiable.OAuth;

/// <summary>
/// Provides human-readable names for <see cref="PolicyProfile"/> values.
/// </summary>
/// <remarks>
/// Mirrors the
/// <see cref="Verifiable.Cryptography.Context.EntropySource"/> companion
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
        var c when c == PolicyProfile.Fapi20.Code => nameof(PolicyProfile.Fapi20),
        var c when c == PolicyProfile.Haip10.Code => nameof(PolicyProfile.Haip10),
        var c when c == PolicyProfile.Rfc6749WithPkce.Code => nameof(PolicyProfile.Rfc6749WithPkce),
        var c when c == PolicyProfile.Oid4VpVerifier.Code => nameof(PolicyProfile.Oid4VpVerifier),
        _ => $"Custom ({code})"
    };
}
