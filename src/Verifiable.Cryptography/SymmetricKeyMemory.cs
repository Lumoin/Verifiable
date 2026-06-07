using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Cryptography;

/// <summary>
/// Memory wrapper for symmetric key material. Holds the bytes of a key that serves
/// both the production and verification halves of a cryptographic operation, where
/// the same bytes are used by every party holding the key.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Distinction from <see cref="PrivateKeyMemory"/>.</strong>
/// <see cref="PrivateKeyMemory"/> holds the private half of an asymmetric key pair.
/// Verification or encryption to that key uses a separate <see cref="PublicKeyMemory"/>.
/// <see cref="SymmetricKeyMemory"/> holds material where one set of bytes serves both
/// production and verification — every party holding the key can both create and check
/// the relevant output. The <see cref="Tag"/>'s <see cref="Verifiable.Cryptography.Context.Purpose"/>
/// distinguishes uses: <see cref="Verifiable.Cryptography.Context.Purpose.Hmac"/> for
/// HMAC keys, <see cref="Verifiable.Cryptography.Context.Purpose.Encryption"/> for AEAD
/// content-encryption keys, <see cref="Verifiable.Cryptography.Context.Purpose.Wrapped"/>
/// for AES key-wrap keys.
/// </para>
/// <para>
/// <strong>Distinction from <see cref="Nonce"/> and <see cref="Salt"/>.</strong>
/// Nonces and salts are random byte sequences whose security derives from uniqueness,
/// not secrecy — both are storable in the clear alongside their use.
/// <see cref="SymmetricKeyMemory"/> holds material whose security derives from being
/// kept secret from anyone not holding it.
/// </para>
/// <para>
/// <strong>Distinction from value types (<see cref="Signature"/>, <see cref="HmacValue"/>,
/// <see cref="Verifiable.Cryptography.Aead.AuthenticationTag"/>, <see cref="DigestValue"/>).</strong>
/// Those are outputs — proofs about data, produced under a key.
/// <see cref="SymmetricKeyMemory"/> is the input — the key under which such outputs are
/// produced and verified.
/// </para>
/// <para>
/// <strong>Distinction from <see cref="Verifiable.Cryptography.Aead.ContentEncryptionKey"/>.</strong>
/// A <see cref="SymmetricKeyMemory"/> holds a key with no single-use lifecycle invariant —
/// the application reuses it as protocol semantics allow. A
/// <see cref="Verifiable.Cryptography.Aead.ContentEncryptionKey"/> is a composition
/// wrapper around a <see cref="SymmetricKeyMemory"/> with an explicit single-use invariant
/// for the ephemeral-CEK case (JWE per-recipient keys derived via ECDH-ES). Long-lived
/// AEAD keys — for example, an authority's encryption key for a Digital Product Passport
/// carrier, rotated periodically — use <see cref="SymmetricKeyMemory"/> directly.
/// Ephemeral derived-per-operation CEKs use the wrapper.
/// </para>
/// </remarks>
[DebuggerDisplay("SymmetricKeyMemory Purpose={Tag.Get<Verifiable.Cryptography.Context.Purpose>()}")]
public class SymmetricKeyMemory: SensitiveMemory
{
    /// <summary>
    /// Initialises a new <see cref="SymmetricKeyMemory"/> from owned memory.
    /// </summary>
    /// <param name="memory">The owned memory containing the key bytes. Ownership transfers to this instance.</param>
    /// <param name="tag">
    /// Metadata identifying the algorithm, purpose, and encoding of the key. The
    /// <see cref="Verifiable.Cryptography.Context.Purpose"/> entry distinguishes intended uses.
    /// </param>
    /// <param name="lifetime">
    /// Optional OTel activity spanning this key's lifetime. Pass <see langword="null"/>
    /// when no OTel listener is active.
    /// </param>
    public SymmetricKeyMemory(IMemoryOwner<byte> memory, Tag tag, Activity? lifetime = null)
        : base(memory, tag, lifetime)
    {
        ArgumentNullException.ThrowIfNull(memory);
        ArgumentNullException.ThrowIfNull(tag);
    }


    /// <summary>
    /// Passes the symmetric key bytes to <paramref name="operation"/> and returns
    /// the result.
    /// </summary>
    /// <remarks>
    /// The key bytes are exposed only for the duration of the delegate call. They remain
    /// owned and protected by this instance throughout. Nothing is captured by closure —
    /// all needed state must be passed via <paramref name="state"/>.
    /// </remarks>
    /// <typeparam name="TArg">The type of the caller-supplied state.</typeparam>
    /// <typeparam name="TResult">The type of the result produced by the operation.</typeparam>
    /// <param name="operation">
    /// The delegate to invoke with the key bytes. Must not store a reference to the memory.
    /// </param>
    /// <param name="state">Caller-supplied state passed through to the operation.</param>
    /// <returns>The result produced by <paramref name="operation"/>.</returns>
    public ValueTask<TResult> WithKeyBytesAsync<TArg, TResult>(
        Func<ReadOnlyMemory<byte>, TArg, ValueTask<TResult>> operation,
        TArg state)
    {
        ArgumentNullException.ThrowIfNull(operation);
        return operation(MemoryOwner.Memory, state);
    }
}
