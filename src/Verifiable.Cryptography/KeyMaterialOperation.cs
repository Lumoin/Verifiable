namespace Verifiable.Cryptography;

/// <summary>
/// The operation callback invoked by a <see cref="WithKeyMaterialDelegate{TResult}"/>
/// once the key material is available in memory. The bytes exposed by
/// <paramref name="keyMaterial"/> are valid only for the duration of this callback.
/// </summary>
/// <typeparam name="TResult">The type produced by the operation.</typeparam>
/// <param name="keyMaterial">
/// The key material bytes. The memory is valid only within this call. The
/// callback must not retain the reference or expose it beyond its own scope.
/// </param>
/// <param name="tag">
/// The tag describing the key, forwarded unchanged from the surrounding
/// <see cref="WithKeyMaterialDelegate{TResult}"/> invocation. Contains the
/// cryptographic algorithm, purpose, encoding, and any application-specific
/// context the operation needs.
/// </param>
/// <param name="cancellationToken">Cancellation token propagated from the caller.</param>
/// <returns>The operation's result.</returns>
/// <remarks>
/// <para>
/// This delegate is the boundary inside which sensitive bytes exist. The
/// enclosing <see cref="WithKeyMaterialDelegate{TResult}"/> handles fetching,
/// unwrapping, or materialisation before invocation, and cleanup after return.
/// The callback runs synchronously with respect to the byte lifetime: once it
/// returns, the bytes are cleared or released.
/// </para>
/// </remarks>
public delegate ValueTask<TResult> KeyMaterialOperation<TResult>(
    ReadOnlyMemory<byte> keyMaterial,
    Tag tag,
    CancellationToken cancellationToken);
