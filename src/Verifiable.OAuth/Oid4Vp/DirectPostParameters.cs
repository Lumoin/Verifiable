using Verifiable.Cryptography.Text;


namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Parameter name constants for the <c>direct_post.jwt</c> response body.
/// </summary>
public static class DirectPostParameters
{
    /// <summary>The UTF-8 source literal of <see cref="Response"/>.</summary>
    public static ReadOnlySpan<byte> ResponseUtf8 => "response"u8;

    /// <summary>
    /// The <c>response</c> parameter carrying the JWE-encrypted authorization response JWT.
    /// </summary>
    public static readonly string Response = Utf8Constants.ToInternedString(ResponseUtf8);
}
