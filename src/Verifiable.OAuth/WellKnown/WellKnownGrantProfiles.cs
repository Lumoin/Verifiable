using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.WellKnown;

/// <summary>
/// The <c>authorization_grant_profiles_supported</c> wire values — the authorization grant profile
/// identifiers registered in the OAuth URI subregistry. Comparison is ordinal.
/// </summary>
public static class WellKnownGrantProfiles
{
    /// <summary>The UTF-8 source literal of <see cref="IdJag"/>.</summary>
    public static ReadOnlySpan<byte> IdJagUtf8 => "urn:ietf:params:oauth:grant-profile:id-jag"u8;

    /// <summary>
    /// The <c>urn:ietf:params:oauth:grant-profile:id-jag</c> Identity Assertion JWT Authorization Grant
    /// profile identifier (draft-ietf-oauth-identity-assertion-authz-grant §7.2 / §8 / §10.2).
    /// </summary>
    public static readonly string IdJag = Utf8Constants.ToInternedString(IdJagUtf8);


    /// <summary>Whether <paramref name="value"/> is <see cref="IdJag"/>.</summary>
    public static bool IsIdJag(string value) => string.Equals(value, IdJag, StringComparison.Ordinal);
}
