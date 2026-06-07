using System.Buffers;

namespace Verifiable.Cryptography;

/// <summary>
/// A scoped-access primitive that materialises the bytes described by
/// <paramref name="tag"/>, invokes <paramref name="operation"/> with the bytes,
/// and releases or clears any transient resources after the operation returns.
/// </summary>
/// <typeparam name="TResult">The type produced by <paramref name="operation"/>.</typeparam>
/// <param name="tag">
/// Describes the key to be materialised. Implementations inspect the tag to
/// decide how to obtain the bytes — direct access for in-memory material,
/// TPM calls for hardware handles, cloud-KMS API calls for remote keys,
/// unwrapping for database-wrapped blobs, and so on. Any application-specific
/// routing metadata is carried in tag entries the application registers.
/// </param>
/// <param name="operation">
/// The callback to invoke with the materialised bytes. The bytes are valid
/// only for the duration of the call. The implementation clears or disposes
/// any transient buffers immediately after the callback returns.
/// </param>
/// <param name="pool">
/// Memory pool used when the implementation needs to allocate transient
/// buffers (for example when unwrapping, decrypting, or copying out of a
/// hardware boundary). Implementations that have no such allocation — direct
/// in-memory lookup — ignore the pool.
/// </param>
/// <param name="cancellationToken">Cancellation token propagated to fetch, unwrap, and the operation.</param>
/// <returns>The result produced by <paramref name="operation"/>.</returns>
/// <remarks>
/// <para>
/// <strong>Purpose</strong>
/// </para>
/// <para>
/// This delegate is the boundary at which a key named by a <see cref="Tag"/>
/// becomes bytes in memory. It handles the "how do I get bytes for this key"
/// concern while keeping the byte lifetime scoped to a single operation
/// invocation. The operation is the place where the bytes are used; the
/// surrounding delegate body handles fetching before and cleanup after.
/// </para>
/// <para>
/// <strong>Relationship to <see cref="PublicKeyMemory.WithKeyBytesAsync"/>
/// and <see cref="PrivateKeyMemory.WithKeyBytesAsync"/></strong>
/// </para>
/// <para>
/// The instance <c>WithKeyBytesAsync</c> methods on <see cref="PublicKeyMemory"/>
/// and <see cref="PrivateKeyMemory"/> operate on an already-materialised memory
/// object — they expose the instance's existing bytes to a callback without
/// fetching, allocation, or async work. They are used by
/// <see cref="PublicKey.VerifyAsync"/> and <see cref="PrivateKey.SignAsync"/>
/// to hand bytes to bound verification and signing functions.
/// </para>
/// <para>
/// <see cref="MaterializeKeyDelegate{TResult}"/> is a different primitive. It
/// starts from a <see cref="Tag"/> that describes where the bytes are (possibly
/// elsewhere — TPM, KMS, wrapped in a database), fetches or materialises them,
/// and only then invokes an operation. The two primitives compose: a
/// <see cref="MaterializeKeyDelegate{TResult}"/> implementation that already has
/// the <see cref="PublicKeyMemory"/> in hand can delegate to that instance's
/// <see cref="PublicKeyMemory.WithKeyBytesAsync"/> for the final byte exposure.
/// </para>
/// <para>
/// <strong>Purpose — JWKS batching</strong>
/// </para>
/// <para>
/// This delegate is not a batch retrieval mechanism. Applications that need to
/// build a JWKS document for a tenant with many keys should query their key
/// store in bulk and apply transformations over the result, rather than invoke
/// this delegate once per key. See the <c>JwksDocumentBuilder</c> helpers in
/// <c>Verifiable.JCose</c> for the batching path.
/// </para>
/// <para>
/// <strong>Typical implementations</strong>
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       Direct in-memory access: the implementation looks up a cached
///       <see cref="PublicKeyMemory"/> or <see cref="PrivateKeyMemory"/> by
///       key identifier carried on the tag and passes its existing memory into
///       <paramref name="operation"/> with no copy.
///     </description>
///   </item>
///   <item>
///     <description>
///       Database-wrapped keys: the implementation fetches the wrapped blob,
///       unwraps into a pooled buffer, passes the buffer into
///       <paramref name="operation"/>, clears and disposes the buffer in a
///       <c>finally</c> block.
///     </description>
///   </item>
///   <item>
///     <description>
///       TPM-backed keys: the implementation interprets the tag's handle bytes,
///       issues the relevant TPM command (for example <c>TPM2_ReadPublic</c> for
///       public-key materialisation), passes the returned bytes into
///       <paramref name="operation"/>, and disposes the pooled result.
///     </description>
///   </item>
///   <item>
///     <description>
///       Cloud-KMS keys: the implementation calls the KMS SDK to fetch the
///       public-key portion (or, for signing, delegates the signing operation
///       itself to the KMS), copies the result into a pooled buffer, and
///       releases the buffer after the operation.
///     </description>
///   </item>
/// </list>
/// <para>
/// <strong>What implementations must not do</strong>
/// </para>
/// <para>
/// Implementations must not retain references to the bytes passed to
/// <paramref name="operation"/> beyond its return, and must not allow the bytes
/// to outlive the scope of this method call. Sensitive memory discipline is the
/// implementation's responsibility — the callback contract alone does not
/// enforce it.
/// </para>
/// </remarks>
public delegate ValueTask<TResult> MaterializeKeyDelegate<TResult>(
    Tag tag,
    KeyMaterialOperation<TResult> operation,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);
