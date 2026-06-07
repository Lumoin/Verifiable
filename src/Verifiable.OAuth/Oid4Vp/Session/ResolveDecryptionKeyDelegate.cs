using Verifiable.Cryptography;

namespace Verifiable.OAuth.Oid4Vp.Session;

/// <summary>
/// A delegate that the application provides to resolve a <see cref="KeyId"/> back to
/// live key material at the exact point in the flow where decryption is needed.
/// </summary>
/// <remarks>
/// <para>
/// The library carries only the <see cref="KeyId"/> through flow state records and never
/// holds, stores, or caches key material itself. The application is responsible for
/// storing the private key scalar under this identifier before the flow is initiated and
/// for resolving it back here when the <c>direct_post.jwt</c> response must be decrypted.
/// </para>
/// <para>
/// The identifier form is determined entirely by the application. It may be a UUID in a
/// local secret store, a KMS key ARN, a DID key identifier, or a JWK <c>kid</c> value.
/// The library treats it as an opaque string.
/// </para>
/// </remarks>
/// <param name="keyId">The identifier carried in the flow state.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The <see cref="PrivateKeyMemory"/> for the key identified by <paramref name="keyId"/>.
/// The caller owns the returned instance and must dispose it after use.
/// </returns>
public delegate ValueTask<PrivateKeyMemory> ResolveDecryptionKeyDelegate(
    KeyId keyId,
    CancellationToken cancellationToken);
