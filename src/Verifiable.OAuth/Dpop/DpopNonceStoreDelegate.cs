namespace Verifiable.OAuth.Dpop;

/// <summary>
/// Stores the nonce an answer from <paramref name="endpoint"/> supplied in its one <c>DPoP-Nonce</c> field, the
/// value the next proof sent to that endpoint carries. The endpoint is the scheme, authority and path of the
/// request URI without query or fragment, the text a proof sent to that endpoint names as its <c>htu</c>.
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 Section 9</see>: "should a client use
/// multiple authorization servers and/or resource servers, a nonce issued by any of them should be used only at
/// the issuing server."
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8.2">Section 8.2</see>: "The client MUST use the new
/// nonce value supplied for the next token request and for all subsequent token requests until the authorization
/// server supplies a new nonce."
/// </summary>
/// <param name="endpoint">The endpoint's scheme, authority and path that supplied the nonce.</param>
/// <param name="nonce">The nonce the endpoint supplied.</param>
public delegate void DpopNonceStoreDelegate(string endpoint, string nonce);
