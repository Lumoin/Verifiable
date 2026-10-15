namespace Verifiable.OAuth.Dpop;

/// <summary>
/// Looks up the most recent DPoP nonce <paramref name="endpoint"/> supplied, or answers
/// <see langword="null"/> when that endpoint has supplied none. The endpoint is the scheme, authority and path
/// of the request URI without query or fragment, the text a proof sent to that endpoint names as its <c>htu</c>,
/// so a nonce is read back only for the endpoint that supplied it.
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 Section 9</see>: "should a client use
/// multiple authorization servers and/or resource servers, a nonce issued by any of them should be used only at
/// the issuing server."
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8.2">Section 8.2</see>: "The client MUST use the new
/// nonce value supplied for the next token request and for all subsequent token requests until the authorization
/// server supplies a new nonce."
/// </summary>
/// <param name="endpoint">The endpoint's scheme, authority and path the nonce was supplied by.</param>
/// <returns>The most recent nonce the endpoint supplied, or <see langword="null"/>.</returns>
public delegate string? DpopNonceLookupDelegate(string endpoint);
