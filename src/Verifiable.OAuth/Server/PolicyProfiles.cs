using System.Diagnostics;
using Verifiable.Core;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Built-in policy profile apply functions and the default
/// <see cref="ResolvePolicyDelegate"/>. Each apply function populates the
/// <see cref="PolicyContextKeys"/> entries on a
/// <see cref="ExchangeContext"/> in one call.
/// </summary>
/// <remarks>
/// <para>
/// Profiles are applied at dispatch entry once per request. Downstream
/// consumers (matchers, validators, token producers) read policy via the
/// typed extensions in <see cref="PolicyExchangeContextExtensions"/>; the
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
    public static void ApplyFapi20(ExchangeContext context)
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
        //Single source of truth: derive the per-flow clock-skew from the
        //deployment's TimingPolicy (the same value AuthCode JAR verification
        //reads directly), falling back to the RFC 7519 §4.1.4 leeway default
        //when no server is on the context (out-of-dispatch / unit-test use).
        context.SetClockSkewTolerance(
            context.Server?.OAuth().Timings.ClockSkewTolerance ?? TimeSpan.FromSeconds(60));
        context.SetEmitIssOnRedirect(true);
        context.SetScopeRequiredOnRequest(true);
        context.SetDiscoveryIssuerShape(IssuerShape.FullUrl);
        context.SetAccessTokenAudPolicy(AccessTokenAudPolicy.Required);
        context.SetIdTokenAudFormat(AudClaimFormat.Either);
        context.SetStateMatchingMode(StateMatchingMode.ExactOrdinal);
        context.SetJtiReplayPolicy(JtiReplayPolicy.Required);
        context.SetRequirePushedAuthorizationRequests(true);
    }


    /// <summary>
    /// Populates the
    /// <see href="https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html">HAIP 1.0</see>
    /// profile. <see cref="ApplyFapi20"/> with HAIP-specific tightenings.
    /// </summary>
    public static void ApplyHaip10(ExchangeContext context)
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
    public static void ApplyRfc6749WithPkce(ExchangeContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        ApplyFapi20(context);
        context.SetAllowedPkceMethods(PkceMethodSet.S256AndPlain);
        context.SetEmitIssOnRedirect(false);
        context.SetScopeRequiredOnRequest(false);
        context.SetAccessTokenAudPolicy(AccessTokenAudPolicy.Optional);
        context.SetJtiReplayPolicy(JtiReplayPolicy.OptionalIfStorePresent);
        //RFC 6749 + PKCE has no PAR mandate; allow the direct and JAR-by-value paths.
        context.SetRequirePushedAuthorizationRequests(false);
    }


    /// <summary>
    /// Populates the OID4VP <em>Verifier</em> (presentation) axes. A focused
    /// profile that does NOT layer <see cref="ApplyFapi20"/>: an OID4VP verifier
    /// registration issues the signed Authorization Request and verifies the
    /// returned <c>vp_token</c>, but exposes no token/authorize endpoint, so the
    /// FAPI 2.0 token-endpoint axes (PKCE, token lifetimes, scope-required,
    /// access/id-token <c>aud</c>, JTI replay) and the inbound-JAR audience/timing
    /// axes do not apply. The OID4VP verification pipeline reads only the two
    /// KB-JWT timing-leeway axes from the policy bag; this sets exactly those.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="PolicyExchangeContextExtensions.SetClockSkewTolerance"/> — 60s,
    /// the RFC 7519 §4.1.4 leeway default, also matching HAIP 1.0 §3's 60-second
    /// ceilings.
    /// </para>
    /// <para>
    /// <see cref="PolicyExchangeContextExtensions.SetKbJwtMaxAgeWindow"/> — 60s.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901</see> requires
    /// the KB-JWT <c>iat</c> to be "within an acceptable window" but pins no
    /// number — it is explicitly the Verifier's policy, because credential
    /// replay/freshness is already guaranteed by the mandatory <c>nonce</c>/<c>aud</c>
    /// binding. 60s is the defense-in-depth window aligned with HAIP §3's
    /// ceilings; deployments override via a custom <see cref="ResolvePolicyDelegate"/>.
    /// </para>
    /// <para>
    /// JAR/request-object lifetimes for the verifier come from
    /// <see cref="Server.TimingPolicy"/> (<c>Oid4VpRequestObjectLifetime</c> /
    /// <c>Oid4VpRequestUriLifetime</c>), not the policy bag, so they are not set here.
    /// </para>
    /// </remarks>
    public static void ApplyOid4VpVerifier(ExchangeContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        //Single source of truth: derive both presentation timing axes from the
        //deployment's TimingPolicy, falling back to the 60s defaults when no
        //server is on the context (out-of-dispatch / unit-test use).
        TimingPolicy? timings = context.Server?.OAuth().Timings;
        context.SetClockSkewTolerance(timings?.ClockSkewTolerance ?? TimeSpan.FromSeconds(60));
        context.SetKbJwtMaxAgeWindow(timings?.KbJwtIatMaxAge ?? TimeSpan.FromSeconds(60));

        //Data minimization: an OID4VP verifier rejects a presentation that
        //discloses more than the DCQL query asked for. Base OID4VP/SD-JWT VC
        //leave this to the holder, so it is configurable — deployments override
        //via a custom ResolvePolicyDelegate; the verifier profile defaults to
        //enforce.
        context.SetEnforceNoOverDisclosure(true);
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
        ExchangeContext context,
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
        else if(profile == PolicyProfile.Oid4VpVerifier)
        {
            ApplyOid4VpVerifier(context);
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
