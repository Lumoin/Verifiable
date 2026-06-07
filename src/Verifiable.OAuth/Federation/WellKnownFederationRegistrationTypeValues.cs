using System;
using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// The wire values an OpenID Provider lists in
/// <see cref="WellKnownFederationClaimNames.ClientRegistrationTypesSupported"/>
/// per <see href="https://openid.net/specs/openid-federation-1_0.html#section-12">Federation §12</see>.
/// </summary>
/// <remarks>
/// <c>automatic</c> (§12.1) admits a Relying Party from an inline trust chain
/// carried on the request without prior registration; <c>explicit</c> (§12.2)
/// registers a Relying Party that POSTs its signed Entity Configuration to the
/// OP's <c>federation_registration_endpoint</c>. An OP may support either or
/// both. Comparison is ordinal — these are protocol tokens, not display text.
/// </remarks>
[DebuggerDisplay("WellKnownFederationRegistrationTypeValues")]
public static class WellKnownFederationRegistrationTypeValues
{
    /// <summary>
    /// <c>automatic</c> — Federation §12.1 automatic registration from an
    /// inline trust chain. Implemented by
    /// <see cref="FederationAutomaticRegistration"/>.
    /// </summary>
    public static readonly string Automatic = "automatic";

    /// <summary>
    /// <c>explicit</c> — Federation §12.2 explicit registration at the
    /// <c>federation_registration_endpoint</c>.
    /// </summary>
    public static readonly string Explicit = "explicit";

    /// <summary>Whether <paramref name="value"/> is <see cref="Automatic"/>.</summary>
    public static bool IsAutomatic(string value) => string.Equals(value, Automatic, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="value"/> is <see cref="Explicit"/>.</summary>
    public static bool IsExplicit(string value) => string.Equals(value, Explicit, StringComparison.Ordinal);
}
