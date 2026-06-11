using Verifiable.Cryptography.Text;


namespace Verifiable.OAuth.Server.Keys;

/// <summary>
/// Stable string constants identifying HMAC use cases for
/// <see cref="SelectHmacKeyDelegate"/>. Selectors may dispatch on these
/// when an application maintains separate keysets per purpose.
/// </summary>
public static class WellKnownHmacPurposes
{
    /// <summary>The UTF-8 source literal of <see cref="DpopNonce"/>.</summary>
    public static ReadOnlySpan<byte> DpopNonceUtf8 => "DpopNonce"u8;

    /// <summary>DPoP nonce HMAC per RFC 9449 — server-internal validation artefacts.</summary>
    public static readonly string DpopNonce = Utf8Constants.ToInternedString(DpopNonceUtf8);
}
