using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth;

/// <summary>
/// Identifies a named policy profile a client registration runs under. Profiles
/// bundle the per-request policy axes into a coherent set
/// (<see cref="PolicyProfile.Fapi20"/>, <see cref="PolicyProfile.Haip10"/>,
/// <see cref="PolicyProfile.Rfc6749WithPkce"/>) shared across server-side
/// enforcement and client-side validation.
/// </summary>
/// <remarks>
/// <para>
/// Follows the dynamic-enum pattern shared with
/// <see cref="Verifiable.OAuth.Server.ServerCapabilityName"/> and
/// <see cref="Verifiable.Cryptography.Context.EntropySource"/>: a readonly
/// struct whose canonical values are static readonly properties, with equality
/// determined by <see cref="Code"/>. Names are looked up via the companion
/// <see cref="PolicyProfileNames"/> class rather than carried on the struct,
/// keeping the value type minimal.
/// </para>
/// <para>
/// The profile choice is a single fact about a registration with two-sided
/// meaning. Server-side dispatchers in
/// <see cref="Verifiable.OAuth.Server.PolicyProfiles"/> apply the per-request
/// enforcement axes (PKCE method set, JAR lifetime ceiling, JTI replay
/// policy, and so on) to the <see cref="Verifiable.OAuth.Server.RequestContext"/>.
/// Client-side dispatchers in
/// <see cref="Verifiable.OAuth.Client.ClientPolicyProfiles"/> resolve the
/// callback validator, PKCE method selection, JAR composition rules, and the
/// expected callback parameter set. Both sides read the same identifier from
/// the registration record their side owns.
/// </para>
/// <para>
/// <strong>Adding a built-in profile.</strong> Library-defined profiles are
/// added by introducing a new static readonly property here (with a fresh
/// code below 1000), wiring its apply functions on each side that needs them,
/// and adding the dispatch arm in the relevant <c>DefaultResolve</c> method.
/// </para>
/// <para>
/// <strong>Adding an application-defined profile.</strong> Tenants with
/// bespoke policy needs use <see cref="Create"/> to register a custom profile
/// (codes 1000 and above to avoid collision with future library additions)
/// and supply their own resolver delegates on either side.
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
    /// FAPI 2.0 Security Profile —
    /// <see href="https://openid.net/specs/fapi-security-profile-2_0-final.html">FAPI 2.0</see>.
    /// The library default when no <c>Profile</c> is set on a registration. See
    /// <see cref="Verifiable.OAuth.Server.PolicyProfiles.ApplyFapi20"/> for the
    /// server-side axes; see
    /// <see cref="Verifiable.OAuth.Client.ClientPolicyProfiles"/> for the
    /// client-side axes.
    /// </summary>
    public static PolicyProfile Fapi20 { get; } = new(0);

    /// <summary>
    /// HAIP 1.0 profile —
    /// <see href="https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html">High
    /// Assurance Interoperability Profile</see>. Layered on top of
    /// <see cref="Fapi20"/> with HAIP-specific tightenings around verifier
    /// metadata, response encryption, and lifetime ceilings.
    /// </summary>
    public static PolicyProfile Haip10 { get; } = new(1);

    /// <summary>
    /// RFC 6749 with PKCE — the permissive baseline that supports PKCE per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636">RFC 7636</see> while
    /// remaining tolerant of pre-FAPI-2 OAuth deployments. Useful for
    /// interoperating with legacy clients that do not implement the
    /// FAPI 2.0 tightenings.
    /// </summary>
    public static PolicyProfile Rfc6749WithPkce { get; } = new(2);


    private static readonly List<PolicyProfile> profiles = [Fapi20, Haip10, Rfc6749WithPkce];

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
    /// Registering a profile here makes the value usable on a registration's
    /// <c>Profile</c> slot, but the library's default resolvers do not know how
    /// to apply application-defined codes. Applications must supply their own
    /// resolver delegates on whichever side handles the custom code, falling
    /// through to the library's default resolver for codes the application
    /// did not register.
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
