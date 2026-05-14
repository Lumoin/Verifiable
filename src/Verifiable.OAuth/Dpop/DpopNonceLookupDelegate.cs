namespace Verifiable.OAuth.Dpop;

/// <summary>
/// Looks up the latest server-issued DPoP nonce for an authority. Returns
/// <see langword="null"/> when no nonce has been cached for the given
/// authority. The authority is the scheme + host + port of the URI per
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8.3">RFC 9449 §8.3</see>.
/// </summary>
public delegate string? DpopNonceLookupDelegate(string authority);
