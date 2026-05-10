using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Identifies a named policy profile a client registration runs under. Profiles
/// bundle the per-request policy axes
/// (<see cref="PolicyContextKeys"/>) into a coherent set
/// (<see cref="PolicyProfile.Strict"/>, <see cref="PolicyProfile.Haip"/>,
/// <see cref="PolicyProfile.Rfc6749"/>) and dispatch via
/// <see cref="PolicyProfiles.DefaultResolvePolicyAsync"/>.
/// </summary>
/// <remarks>
/// <para>
/// Follows the dynamic-enum pattern shared with
/// <see cref="ServerCapabilityName"/> and
/// <see cref="Verifiable.Cryptography.Context.EntropySource"/>: a readonly
/// struct whose canonical values are static readonly properties, with equality
/// determined by <see cref="Code"/>. Names are looked up via the companion
/// <see cref="PolicyProfileNames"/> class rather than carried on the struct,
/// keeping the value type minimal.
/// </para>
/// <para>
/// <strong>Adding a built-in profile.</strong> Library-defined profiles are
/// added by introducing a new static readonly property here (with a fresh
/// code below 1000), wiring its apply function in
/// <see cref="PolicyProfiles"/>, and adding its dispatch arm in
/// <see cref="PolicyProfiles.DefaultResolvePolicyAsync"/>.
/// </para>
/// <para>
/// <strong>Adding an application-defined profile.</strong> Tenants with
/// bespoke policy needs use <see cref="Create"/> to register a custom profile
/// (codes 1000 and above to avoid collision with future library additions)
/// and supply their own
/// <see cref="ResolvePolicyDelegate"/> via
/// <see cref="AuthorizationServerIntegration.ResolvePolicyAsync"/>. The
/// custom delegate handles the application's codes; for codes it does not
/// recognise it can fall through to
/// <see cref="PolicyProfiles.DefaultResolvePolicyAsync"/>, which applies
/// <see cref="Strict"/> as a fail-safe default.
/// </para>
/// <para>
/// <strong>Persistence.</strong> The type is an identifier, not a
/// configuration shape. Applications persist registrations with whatever
/// column type fits their store — most commonly an <see cref="int"/> column
/// holding <see cref="Code"/>, or a small JSONB document. The library does
/// not impose a string-name persistence shape; the registration loader is
/// free to deserialise directly to <see cref="PolicyProfile"/>. User-facing
/// surfaces (admin UIs, configuration files, API responses) typically
/// encode the name via <see cref="PolicyProfileNames.GetName(PolicyProfile)"/>
/// for human readability.
/// </para>
/// </remarks>
[DebuggerDisplay("{PolicyProfileNames.GetName(this),nq}")]
public readonly struct PolicyProfile: IEquatable<PolicyProfile>
{
    /// <summary>Gets the numeric code identifying this profile.</summary>
    public int Code { get; }

    private PolicyProfile(int code)
    {
        Code = code;
    }


    /// <summary>
    /// FAPI 2.0-aligned strict reading. The library default when no
    /// <see cref="ClientRegistration.Profile"/> is set on a registration.
    /// See <see cref="PolicyProfiles.ApplyStrict"/> for the populated axes.
    /// </summary>
    public static PolicyProfile Strict { get; } = new(0);

    /// <summary>
    /// HAIP 1.0 profile —
    /// <see href="https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html">High
    /// Assurance Interoperability Profile</see> — Strict with HAIP-specific
    /// tightenings. See <see cref="PolicyProfiles.ApplyHaip"/>.
    /// </summary>
    public static PolicyProfile Haip { get; } = new(1);

    /// <summary>
    /// Permissive RFC 6749 baseline — useful for pre-FAPI-2 OAuth
    /// deployments interoperating with legacy clients. See
    /// <see cref="PolicyProfiles.ApplyRfc6749Baseline"/>.
    /// </summary>
    public static PolicyProfile Rfc6749 { get; } = new(2);


    private static readonly List<PolicyProfile> profiles = [Strict, Haip, Rfc6749];

    /// <summary>Gets all registered profile values including any custom ones.</summary>
    public static IReadOnlyList<PolicyProfile> Profiles => profiles.AsReadOnly();


    /// <summary>
    /// Creates a new <see cref="PolicyProfile"/> for an application-defined
    /// profile.
    /// </summary>
    /// <param name="code">
    /// The numeric code identifying the profile. Use values <strong>1000 and
    /// above</strong> to avoid collisions with future library additions.
    /// </param>
    /// <returns>The newly registered profile.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="code"/> is already registered.</exception>
    /// <remarks>
    /// <para>
    /// Registering a profile here makes the value usable on
    /// <see cref="ClientRegistration.Profile"/>, but the library's
    /// default resolver does not know how to apply application-defined
    /// codes. Applications must supply their own
    /// <see cref="ResolvePolicyDelegate"/> via
    /// <see cref="AuthorizationServerIntegration.ResolvePolicyAsync"/> that
    /// dispatches the custom code to its own apply logic. The custom
    /// delegate is free to fall through to
    /// <see cref="PolicyProfiles.DefaultResolvePolicyAsync"/> for codes it
    /// does not recognise.
    /// </para>
    /// <para>
    /// <strong>Worked example.</strong>
    /// </para>
    /// <code>
    /// // Application startup — register the custom profile and apply function.
    /// public static class FintechProfiles
    /// {
    ///     public static PolicyProfile FintechStrict { get; } = PolicyProfile.Create(1000);
    ///
    ///     public static void ApplyFintechStrict(RequestContext context)
    ///     {
    ///         PolicyProfiles.ApplyStrict(context);
    ///         context.SetClockSkewTolerance(TimeSpan.FromSeconds(30));
    ///         context.SetJarLifetimeCeiling(TimeSpan.FromSeconds(30));
    ///     }
    /// }
    ///
    /// // Custom resolver wired into AuthorizationServerIntegration.
    /// integration.ResolvePolicyAsync = (registration, context, ct) =>
    /// {
    ///     PolicyProfile profile = registration.Profile ?? PolicyProfile.Strict;
    ///     if(profile == FintechProfiles.FintechStrict)
    ///     {
    ///         FintechProfiles.ApplyFintechStrict(context);
    ///         return ValueTask.CompletedTask;
    ///     }
    ///
    ///     // Fall through to the library's default for codes we did not register.
    ///     return PolicyProfiles.DefaultResolvePolicyAsync(registration, context, ct);
    /// };
    /// </code>
    /// </remarks>
    public static PolicyProfile Create(int code)
    {
        for(int i = 0; i < profiles.Count; ++i)
        {
            if(profiles[i].Code == code)
            {
                throw new ArgumentException(
                    $"A policy profile with code {code} is already registered.", nameof(code));
            }
        }

        PolicyProfile newProfile = new(code);
        profiles.Add(newProfile);
        return newProfile;
    }


    /// <inheritdoc/>
    public override string ToString() => PolicyProfileNames.GetName(this);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(PolicyProfile other) => Code == other.Code;


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is PolicyProfile other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Code;


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(PolicyProfile left, PolicyProfile right) =>
        left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(PolicyProfile left, PolicyProfile right) =>
        !left.Equals(right);
}
