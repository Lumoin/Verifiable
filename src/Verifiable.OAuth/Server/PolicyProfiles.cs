using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Built-in policy profile apply functions and the default
/// <see cref="ResolvePolicyDelegate"/>. Each apply function populates the
/// <see cref="PolicyContextKeys"/> entries on a
/// <see cref="RequestContext"/> in one call.
/// </summary>
/// <remarks>
/// <para>
/// Profiles are applied at dispatch entry once per request. Downstream
/// consumers (matchers, validators, token producers) read policy via the
/// typed extensions in <see cref="PolicyRequestContextExtensions"/>; the
/// extensions return strict defaults when a key is absent, so a request
/// processed without a profile having been applied still produces the
/// safest behaviour.
/// </para>
/// <para>
/// Adding a built-in profile means adding a new <c>ApplyXxx</c> function
/// here plus a new static readonly value on <see cref="PolicyProfile"/>
/// plus a dispatch arm in <see cref="DefaultResolvePolicyAsync"/>.
/// Tenant-specific profiles do not modify this class; instead they use
/// <see cref="PolicyProfile.Create"/> and supply a custom
/// <see cref="ResolvePolicyDelegate"/>. See the remarks on
/// <see cref="PolicyProfile"/> for the full extensibility shape.
/// </para>
/// </remarks>
[DebuggerDisplay("PolicyProfiles")]
public static class PolicyProfiles
{
    /// <summary>
    /// Populates the FAPI 2.0-aligned strict reading. Used as the default
    /// when no <see cref="ClientRegistration.Profile"/> is set, and as the
    /// base for <see cref="ApplyHaip"/>.
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
    /// on <see cref="ClientRegistration.Profile"/> across the three shipped
    /// profiles via <see cref="PolicyProfile"/> code equality; falls back to
    /// <see cref="ApplyStrict"/> when the profile is absent or
    /// application-defined (the application's own resolver handles its own
    /// codes; this default is the fail-safe baseline).
    /// </summary>
    public static ValueTask DefaultResolvePolicyAsync(
        ClientRegistration registration,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        PolicyProfile profile = registration.Profile ?? PolicyProfile.Strict;

        if(profile == PolicyProfile.Strict)
        {
            ApplyStrict(context);
        }
        else if(profile == PolicyProfile.Haip)
        {
            ApplyHaip(context);
        }
        else if(profile == PolicyProfile.Rfc6749)
        {
            ApplyRfc6749Baseline(context);
        }
        else
        {
            //Unknown custom code — application must supply its own
            //ResolvePolicyDelegate to handle codes it registered via
            //PolicyProfile.Create. Falling back to strict is fail-safe.
            ApplyStrict(context);
        }

        return ValueTask.CompletedTask;
    }
}
