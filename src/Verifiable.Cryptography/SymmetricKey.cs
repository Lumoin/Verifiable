using System.Collections.Frozen;
using System.Diagnostics;

namespace Verifiable.Cryptography;

/// <summary>
/// A symmetric key with bound HMAC compute and verify functions. Parallel to
/// <see cref="PrivateKey"/> for the asymmetric column.
/// </summary>
/// <remarks>
/// <para>
/// Holds long-lived HMAC keys whose backend dispatch is resolved once at
/// construction time and reused across many compute/verify operations without
/// re-resolving from the registry per call.
/// </para>
/// <para>
/// The default <paramref name="defaultContext"/> applies to every operation that
/// does not pass its own context. Use cases include FAPI 2.0 deployments that
/// thread an audience identifier or policy code through every HMAC verification.
/// </para>
/// </remarks>
[DebuggerDisplay("SymmetricKey Id={Id,nq}")]
public sealed class SymmetricKey: SensitiveMemoryKey
{
    private readonly ComputeHmacDelegate computeHmac;
    private readonly VerifyHmacDelegate verifyHmac;
    private readonly FrozenDictionary<string, object>? defaultContext;


    /// <summary>
    /// Returns the underlying symmetric key memory typed as
    /// <see cref="SymmetricKeyMemory"/>.
    /// </summary>
    private new SymmetricKeyMemory KeyMaterial => (SymmetricKeyMemory)base.KeyMaterial;


    /// <summary>
    /// Initialises a new <see cref="SymmetricKey"/>.
    /// </summary>
    /// <param name="keyMaterial">The symmetric key memory. Ownership transfers to this instance.</param>
    /// <param name="id">A unique identifier for the key (DID URL, key id, etc.).</param>
    /// <param name="computeHmac">The bound HMAC compute delegate.</param>
    /// <param name="verifyHmac">The bound HMAC verify delegate.</param>
    /// <param name="defaultContext">Optional default context applied when call sites omit theirs.</param>
    public SymmetricKey(
        SymmetricKeyMemory keyMaterial,
        string id,
        ComputeHmacDelegate computeHmac,
        VerifyHmacDelegate verifyHmac,
        FrozenDictionary<string, object>? defaultContext = null)
        : base(keyMaterial, id)
    {
        ArgumentNullException.ThrowIfNull(computeHmac);
        ArgumentNullException.ThrowIfNull(verifyHmac);

        this.computeHmac = computeHmac;
        this.verifyHmac = verifyHmac;
        this.defaultContext = defaultContext;
    }


    /// <summary>
    /// Computes an HMAC over <paramref name="message"/> using the bound key and delegate.
    /// </summary>
    public ValueTask<HmacValue> ComputeHmacAsync(
        ReadOnlyMemory<byte> message,
        int outputByteLength,
        System.Buffers.MemoryPool<byte> pool,
        FrozenDictionary<string, object>? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);
        return KeyMaterial.ComputeHmacAsync(
            message, outputByteLength, computeHmac, pool, context ?? defaultContext, cancellationToken);
    }


    /// <summary>
    /// Verifies <paramref name="expectedMac"/> against an HMAC of
    /// <paramref name="message"/> using the bound key and delegate.
    /// </summary>
    public ValueTask<bool> VerifyHmacAsync(
        ReadOnlyMemory<byte> message,
        HmacValue expectedMac,
        System.Buffers.MemoryPool<byte> pool,
        FrozenDictionary<string, object>? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(expectedMac);
        ArgumentNullException.ThrowIfNull(pool);
        return KeyMaterial.VerifyHmacAsync(
            message, expectedMac, verifyHmac, pool, context ?? defaultContext, cancellationToken);
    }


    /// <summary>
    /// Verifies <paramref name="expectedMacBytes"/> against an HMAC of
    /// <paramref name="message"/> using the bound key and delegate.
    /// </summary>
    public ValueTask<bool> VerifyHmacAsync(
        ReadOnlyMemory<byte> message,
        ReadOnlyMemory<byte> expectedMacBytes,
        System.Buffers.MemoryPool<byte> pool,
        FrozenDictionary<string, object>? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);
        return KeyMaterial.VerifyHmacAsync(
            message, expectedMacBytes, verifyHmac, pool, context ?? defaultContext, cancellationToken);
    }
}
