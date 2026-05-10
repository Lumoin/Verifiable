using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Built-in policy profiles that populate the
/// <see cref="PolicyContextKeys"/> entries on a <see cref="RequestContext"/>
/// in one call. The default
/// <see cref="ResolvePolicyDelegate"/> dispatches on
/// <see cref="ClientRegistration.ProfileName"/> across the three profiles
/// shipped here.
/// </summary>
/// <remarks>
/// <para>
/// Profiles are applied at dispatch entry once per request. Downstream
/// consumers (matchers, validators, token producers) read policy via the
/// typed extensions in <see cref="PolicyRequestContextExtensions"/>; the
/// extensions return the strict default when a key is absent, so a request
/// processed without a profile having been applied still produces the
/// safest behaviour.
/// </para>
/// <para>
/// Defining a new profile is one new function on this class plus a
/// <c>case</c> entry in <see cref="DefaultResolvePolicyAsync"/>. Applications
/// with bespoke policy needs supply their own
/// <see cref="ResolvePolicyDelegate"/> via
/// <see cref="AuthorizationServerIntegration.ResolvePolicyAsync"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("PolicyProfiles")]
public static class PolicyProfiles
{
    /// <summary>The named-profile value for <see cref="ApplyStrict"/>.</summary>
    public static readonly string Strict = "strict";

    /// <summary>The named-profile value for <see cref="ApplyHaip"/>.</summary>
    public static readonly string Haip = "haip";

    /// <summary>The named-profile value for <see cref="ApplyRfc6749Baseline"/>.</summary>
    public static readonly string Rfc6749 = "rfc6749";


    /// <summary>
    /// Populates the FAPI 2.0-aligned strict reading. Used as the default
    /// when no <see cref="ClientRegistration.ProfileName"/> is set, and as
    /// the base for <see cref="ApplyHaip"/>.
    /// </summary>
    public static void ApplyStrict(RequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        context.SetJarAudienceValidation(JarAudienceMode.IssuerOnly);
        context.SetRequiredJarTimingClaims(TimingClaimSet.All);
        context.SetJarLifetimeCeiling(TimeSpan.FromSeconds(60));
        context.SetAllowedPkceMethods(PkceMethodSet.S256Only);
        context.SetAuthorizationCodeLifetime(TimeSpan.FromSeconds(600));
        context.SetAccessTokenLifetime(TimeSpan.FromHours(1));
        context.SetIdTokenLifetime(TimeSpan.FromHours(1));
        context.SetRequestUriLifetime(TimeSpan.FromSeconds(60));
        context.SetClockSkewTolerance(TimeSpan.FromSeconds(60));
        context.SetEmitIssOnRedirect(true);
        context.SetScopeRequiredOnRequest(true);
        context.SetDiscoveryIssuerShape(IssuerShape.FullUrl);
        context.SetAccessTokenAudPolicy(AccessTokenAudPolicy.Required);
        context.SetIdTokenAudFormat(AudClaimFormat.Either);
        context.SetStateMatchingMode(StateMatchingMode.ExactOrdinal);
        context.SetJtiReplayPolicy(JtiReplayPolicy.Required);
    }


    /// <summary>
    /// Populates the
    /// <see href="https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html">HAIP 1.0</see>
    /// profile. <see cref="ApplyStrict"/> with HAIP-specific tightenings.
    /// </summary>
    public static void ApplyHaip(RequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        ApplyStrict(context);
        //HAIP §3 mandates 60-second lifetime ceilings throughout — already
        //the default in ApplyStrict but pinned here for clarity. HAIP-specific
        //axes that the library does not yet expose (for example mandatory
        //A128GCM/A256GCM advertisement on verifier client metadata) live
        //outside the policy bag on VerifierClientMetadata directly.
        context.SetJarLifetimeCeiling(TimeSpan.FromSeconds(60));
        context.SetRequestUriLifetime(TimeSpan.FromSeconds(60));
    }


    /// <summary>
    /// Populates the permissive RFC 6749 baseline reading. Useful for
    /// pre-FAPI-2 OAuth deployments interoperating with legacy clients.
    /// </summary>
    public static void ApplyRfc6749Baseline(RequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        ApplyStrict(context);
        context.SetAllowedPkceMethods(PkceMethodSet.S256AndPlain);
        context.SetEmitIssOnRedirect(false);
        context.SetScopeRequiredOnRequest(false);
        context.SetAccessTokenAudPolicy(AccessTokenAudPolicy.Optional);
        context.SetJtiReplayPolicy(JtiReplayPolicy.OptionalIfStorePresent);
    }


    /// <summary>
    /// The library's default <see cref="ResolvePolicyDelegate"/>. Dispatches
    /// on <see cref="ClientRegistration.ProfileName"/> across the three
    /// shipped profiles; falls back to <see cref="ApplyStrict"/> when the
    /// profile name is unrecognised or absent.
    /// </summary>
    public static ValueTask DefaultResolvePolicyAsync(
        ClientRegistration registration,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        string profileName = registration.ProfileName ?? Strict;

        switch(profileName)
        {
            case var name when string.Equals(name, Strict, StringComparison.Ordinal):
            {
                ApplyStrict(context);
                break;
            }
            case var name when string.Equals(name, Haip, StringComparison.Ordinal):
            {
                ApplyHaip(context);
                break;
            }
            case var name when string.Equals(name, Rfc6749, StringComparison.Ordinal):
            {
                ApplyRfc6749Baseline(context);
                break;
            }
            default:
            {
                ApplyStrict(context);
                break;
            }
        }

        return ValueTask.CompletedTask;
    }
}
