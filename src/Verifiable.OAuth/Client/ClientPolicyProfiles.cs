using System.Diagnostics;
using Verifiable.Core.Assessment;
using Verifiable.OAuth.Validation;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Built-in client-side policy profile resolvers. Mirrors the structure of
/// <see cref="Verifiable.OAuth.Server.PolicyProfiles"/>: each resolver
/// dispatches on a registration's <see cref="ClientRegistration.Profile"/>
/// and returns the per-axis value the corresponding client-side handler
/// needs.
/// </summary>
/// <remarks>
/// <para>
/// One resolver method per profile-bound axis. The library currently ships
/// the callback-validator axis through
/// <see cref="DefaultResolveCallbackValidator"/>; additional axes (PKCE
/// method selection, JAR composition, expected callback parameter set,
/// ID-token validation rule set) land as sibling methods here as their
/// flows arrive.
/// </para>
/// <para>
/// Applications wire one or more of these defaults onto
/// <see cref="OAuthClientInfrastructure"/> when constructing a client.
/// Tenants with custom profiles supply their own resolver delegates and
/// typically fall through to the library defaults for codes they do not
/// own.
/// </para>
/// </remarks>
[DebuggerDisplay("ClientPolicyProfiles")]
public static class ClientPolicyProfiles
{
    /// <summary>
    /// The library's default <see cref="ResolveCallbackValidatorDelegate"/>.
    /// Dispatches on <see cref="ClientRegistration.Profile"/> across the
    /// three shipped profiles; falls back to
    /// <see cref="PolicyProfile.Fapi20"/> when the profile is absent or
    /// application-defined.
    /// </summary>
    /// <remarks>
    /// The FAPI 2.0 and HAIP 1.0 callback rule sets currently coincide —
    /// both consume the rules returned by
    /// <see cref="ValidationProfiles.CallbackHaip10Rules"/> — but the issuer
    /// labels differ so audit trails and diagnostics distinguish them.
    /// </remarks>
    public static ClaimIssuer<ValidationContext> DefaultResolveCallbackValidator(
        ClientRegistration registration,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(timeProvider);

        PolicyProfile profile = registration.Profile ?? PolicyProfile.Fapi20;

        if(profile == PolicyProfile.Fapi20)
        {
            return new ClaimIssuer<ValidationContext>(
                "callback-fapi20",
                ValidationProfiles.CallbackHaip10Rules(),
                timeProvider);
        }
        if(profile == PolicyProfile.Haip10)
        {
            return new ClaimIssuer<ValidationContext>(
                "callback-haip10",
                ValidationProfiles.CallbackHaip10Rules(),
                timeProvider);
        }
        if(profile == PolicyProfile.Rfc6749WithPkce)
        {
            return new ClaimIssuer<ValidationContext>(
                "callback-rfc6749-pkce",
                ValidationProfiles.CallbackRfc6749WithPkceRules(),
                timeProvider);
        }

        //Unknown custom code — fall back to FAPI 2.0 as the fail-safe default.
        //Applications that ship custom profiles supply their own resolver and
        //typically delegate here for codes they did not register.
        return new ClaimIssuer<ValidationContext>(
            "callback-fapi20",
            ValidationProfiles.CallbackHaip10Rules(),
            timeProvider);
    }


    /// <summary>
    /// Returns <see langword="true"/> when the given policy profile mandates
    /// DPoP-bound access tokens. <see cref="PolicyProfile.Haip10"/> and
    /// <see cref="PolicyProfile.Fapi20"/> both require DPoP at the token
    /// endpoint; <see cref="PolicyProfile.Rfc6749WithPkce"/> and
    /// <see langword="null"/> profiles do not.
    /// </summary>
    public static bool RequiresDpop(PolicyProfile? profile) =>
        profile is { } p && (p == PolicyProfile.Haip10 || p == PolicyProfile.Fapi20);
}
