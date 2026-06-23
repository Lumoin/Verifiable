using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.WellKnown;

/// <summary>
/// The <c>client_assertion_type</c> wire values per
/// <see href="https://www.rfc-editor.org/rfc/rfc7521#section-4.2">RFC 7521 §4.2</see>. Comparison is ordinal.
/// </summary>
public static class WellKnownClientAssertionTypes
{
    /// <summary>The UTF-8 source literal of <see cref="JwtBearer"/>.</summary>
    public static ReadOnlySpan<byte> JwtBearerUtf8 => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"u8;

    /// <summary>
    /// The <c>urn:ietf:params:oauth:client-assertion-type:jwt-bearer</c> value — the RFC 7523 §2.2 JWT
    /// client-authentication profile (<c>private_key_jwt</c> / <c>client_secret_jwt</c>).
    /// </summary>
    public static readonly string JwtBearer = Utf8Constants.ToInternedString(JwtBearerUtf8);


    /// <summary>Whether <paramref name="value"/> is <see cref="JwtBearer"/>.</summary>
    public static bool IsJwtBearer(string value) => string.Equals(value, JwtBearer, StringComparison.Ordinal);
}
