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
    /// Populates the FAPI 2.0 Security Profile axes. Used as the default
    /// when no <c>Profile</c> is set on a registration, and as the base for
    /// <see cref="ApplyHaip10"/>.
    /// </summary>
    public static void ApplyFapi20(RequestContext context)
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
    /// profile. <see cref="ApplyFapi20"/> with HAIP-specific tightenings.
    /// </summary>
    public static void ApplyHaip10(RequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        ApplyFapi20(context);
        //HAIP §3 mandates 60-second lifetime ceilings throughout — already
        //the default in ApplyFapi20 but pinned here for clarity. HAIP-specific
        //axes that the library does not yet expose (for example mandatory
        //A128GCM/A256GCM advertisement on verifier client metadata) live
        //outside the policy bag on VerifierClientMetadata directly.
        context.SetJarLifetimeCeiling(TimeSpan.FromSeconds(60));
        context.SetRequestUriLifetime(TimeSpan.FromSeconds(60));
    }


    /// <summary>
    /// Populates the RFC 6749 with PKCE baseline. Permissive relative to
    /// <see cref="ApplyFapi20"/> — supports PKCE methods beyond S256, relaxes
    /// the <c>iss</c>-on-redirect requirement, and relaxes the
    /// scope-required-on-request requirement. Useful for interoperating with
    /// pre-FAPI-2 OAuth deployments that still want PKCE protection.
    /// </summary>
    public static void ApplyRfc6749WithPkce(RequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        ApplyFapi20(context);
        context.SetAllowedPkceMethods(PkceMethodSet.S256AndPlain);
        context.SetEmitIssOnRedirect(false);
        context.SetScopeRequiredOnRequest(false);
        context.SetAccessTokenAudPolicy(AccessTokenAudPolicy.Optional);
        context.SetJtiReplayPolicy(JtiReplayPolicy.OptionalIfStorePresent);
    }


    /// <summary>
    /// The library's default <see cref="ResolvePolicyDelegate"/>. Dispatches
    /// on the registration's <c>Profile</c> across the three shipped
    /// profiles via <see cref="PolicyProfile"/> code equality; falls back to
    /// <see cref="ApplyFapi20"/> when the profile is absent or
    /// application-defined (the application's own resolver handles its own
    /// codes; this default is the fail-safe baseline).
    /// </summary>
    public static ValueTask DefaultResolvePolicyAsync(
        ClientRecord registration,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        PolicyProfile profile = registration.Profile ?? PolicyProfile.Fapi20;

        if(profile == PolicyProfile.Fapi20)
        {
            ApplyFapi20(context);
        }
        else if(profile == PolicyProfile.Haip10)
        {
            ApplyHaip10(context);
        }
        else if(profile == PolicyProfile.Rfc6749WithPkce)
        {
            ApplyRfc6749WithPkce(context);
        }
        else
        {
            //Unknown custom code — application must supply its own
            //ResolvePolicyDelegate to handle codes it registered via
            //PolicyProfile.Create. Falling back to Fapi20 is fail-safe.
            ApplyFapi20(context);
        }

        return ValueTask.CompletedTask;
    }
}
