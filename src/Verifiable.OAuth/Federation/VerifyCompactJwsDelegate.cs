using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Verifies a compact JWS against a resolved public key, returning whether the signature is valid.
/// <see cref="FederationTrustMarkResolver"/> resolves the signer's key from the chain (via
/// <see cref="FederationKeyResolver.ResolveInChainKeyAsync"/>) and hands it to this app-supplied delegate, which
/// wraps the JWS-verify primitive (<c>Jws.VerifyAsync</c>) with the deployment's crypto provider. Keeping key
/// resolution (library) separate from the signature primitive (app) mirrors <see cref="ResolveEntityKeyDelegate"/>.
/// </summary>
/// <param name="compactJws">The compact JWS to verify (a trust mark or its delegation).</param>
/// <param name="key">The resolved signer key the signature is checked against.</param>
/// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
/// <returns><see langword="true"/> when the signature verifies against <paramref name="key"/>.</returns>
[DebuggerDisplay("VerifyCompactJwsDelegate")]
public delegate ValueTask<bool> VerifyCompactJwsDelegate(
    string compactJws,
    PublicKeyMemory key,
    CancellationToken cancellationToken);
