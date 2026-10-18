using Verifiable.Cryptography;

namespace Verifiable.OAuth;

/// <summary>
/// Resolves the public key a party publishes under the <c>kid</c> a compact JWS's protected header names, bound to the one
/// algorithm that header names (<see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.1">RFC 8725 §3.1</see>: "Each key
/// MUST be used with exactly one algorithm"): the seam a client verifying an OpenID Provider's ID Token or an identity
/// assertion grant reads the provider's key through, the key set's fetch and its selection policy being the application's.
/// </summary>
/// <remarks>
/// The library reads the header (<see cref="UnverifiedJwsFacts.Read"/>) and asks for the key by its <c>kid</c> and <c>alg</c>;
/// the resolver answers a key usable under that algorithm alone, or <see langword="null"/> where the set names no such key,
/// names one of another algorithm, or could not be read. The library owns and disposes the key it is answered.
/// </remarks>
/// <param name="keyId">The <c>kid</c> the header names.</param>
/// <param name="algorithm">The <c>alg</c> the header names.</param>
/// <param name="cancellationToken">Cancels the key set's read.</param>
/// <returns>The key, which the caller disposes, or <see langword="null"/>.</returns>
public delegate ValueTask<PublicKeyMemory?> ResolveJwsVerificationKeyDelegate(string keyId, string algorithm, CancellationToken cancellationToken);
