namespace Verifiable.OAuth.Dpop;

/// <summary>
/// Stores a server-issued DPoP nonce extracted from a <c>DPoP-Nonce</c>
/// response header. The cached value is used on the next request to the
/// same authority.
/// </summary>
public delegate void DpopNonceStoreDelegate(string authority, string nonce);
