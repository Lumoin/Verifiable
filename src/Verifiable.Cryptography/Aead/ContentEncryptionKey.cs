using System.Diagnostics;
using System.Threading;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// A single-use content encryption key. Wraps a <see cref="SymmetricKeyMemory"/> with
/// explicit one-shot ownership-transfer semantics, used for ephemeral CEKs derived
/// per AEAD operation — JWE per-recipient keys derived via ECDH-ES, similar
/// short-lived key material that must not be reused.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why composition rather than <c>: SymmetricKeyMemory</c>.</strong>
/// Inheritance would expose <see cref="ContentEncryptionKey"/> instances at any
/// <see cref="SymmetricKeyMemory"/> parameter slot — AEAD encrypt and decrypt paths,
/// HMAC compute paths, future persistent-AEAD paths. Those paths legitimately type
/// their parameter as the broad symmetric type; a CEK passed through such a slot
/// would lose its single-use signal. Type slicing on a runtime lifecycle invariant
/// the supertype's code paths do not see. Composition removes the problem:
/// <see cref="ContentEncryptionKey"/> does not derive from <see cref="SymmetricKeyMemory"/>,
/// so the conversion is unavailable and the slicing path does not exist.
/// </para>
/// <para>
/// <strong>Distinction from <see cref="Verifiable.Cryptography.Nonce.UseNonce"/>.</strong>
/// Both types model single-use cryptographic material. <see cref="Verifiable.Cryptography.Nonce"/>
/// is a <see cref="SensitiveMemory"/> subclass that exposes its bytes via the base
/// <see cref="SensitiveMemory.AsReadOnlySpan"/> accessor; consequently
/// <see cref="Verifiable.Cryptography.Nonce.UseNonce"/> cannot prevent a second
/// access — it only makes the second access observable via
/// <see cref="Verifiable.Cryptography.Nonce.UseCount"/> and the OTel lifetime span.
/// The <c>UseNonce</c> docs are explicit about this: "This method is not enforced".
/// </para>
/// <para>
/// <see cref="ContentEncryptionKey"/> is a composition wrapper, not a
/// <see cref="SensitiveMemory"/> subclass. It does not expose its inner key through
/// any base accessor — <see cref="UseKey"/> is the only path to the underlying
/// <see cref="SymmetricKeyMemory"/>. This structural difference allows enforced
/// single-use: a second <see cref="UseKey"/> call throws
/// <see cref="InvalidOperationException"/>. The stronger guarantee is appropriate
/// because <see cref="UseKey"/> returns a heap-allocated <see cref="SymmetricKeyMemory"/>
/// that can be stored, captured in a closure, or passed across <c>await</c>
/// boundaries — the misuse blast radius of a second consumption is materially
/// larger than <c>UseNonce</c>'s stack-only <see cref="ReadOnlySpan{T}"/> return.
/// </para>
/// <para>
/// The two patterns reflect different structural choices, each honest about what
/// it can enforce given its type relationship to <see cref="SensitiveMemory"/>.
/// Consistency is preserved at the level of intent codification: both types name
/// the consumption method, increment an observable <c>UseCount</c>, and fire OTel
/// telemetry. They differ on whether a second consumption proceeds with a counter
/// signal (<see cref="Verifiable.Cryptography.Nonce"/>) or throws atomically
/// (<see cref="ContentEncryptionKey"/>), and the documentation makes the difference
/// and its reason explicit.
/// </para>
/// <para>
/// <strong>Distinction from <see cref="SymmetricKeyMemory"/> directly.</strong>
/// A <see cref="SymmetricKeyMemory"/> with
/// <see cref="Verifiable.Cryptography.Context.Purpose.Encryption"/> holds a
/// persistent AEAD key — for example a Digital Product Passport encryption key held
/// by an issuing authority and reused across many payloads over its lifetime,
/// rotated periodically. Use <see cref="SymmetricKeyMemory"/> directly for that
/// case. Use <see cref="ContentEncryptionKey"/> only when the key is derived
/// per-operation via KDF and must not be reused — JWE ECDH-ES per-recipient CEKs,
/// ECDH-1PU CEKs in DIDComm v2 authcrypt, similar.
/// </para>
/// <para>
/// <strong>Usage.</strong> Hold the <see cref="ContentEncryptionKey"/> for the
/// duration of CEK derivation. At the moment the AEAD operation runs, call
/// <see cref="UseKey"/> to obtain the inner <see cref="SymmetricKeyMemory"/>; the
/// wrapper becomes empty. Pass the obtained key to the AEAD delegate. Dispose the
/// key after the operation.
/// </para>
/// <code>
/// using ContentEncryptionKey cek = await deriveCekDelegate(sharedSecret, ...);
/// using SymmetricKeyMemory key = cek.UseKey();
/// AeadEncryptResult result = await aeadEncryptDelegate(plaintext, key, aad, pool);
/// </code>
/// </remarks>
[DebuggerDisplay("ContentEncryptionKey UseCount={UseCount} Consumed={inner is null}")]
public sealed class ContentEncryptionKey: IDisposable
{
    private SymmetricKeyMemory? inner;
    private int useCount;
    private bool disposed;
    private readonly System.Diagnostics.Activity? lifetime;


    /// <summary>
    /// The number of times <see cref="UseKey"/> has been called. Reflects every
    /// invocation including ones that threw because the key was already consumed.
    /// </summary>
    public int UseCount => useCount;


    /// <summary>
    /// The <see cref="Tag"/> of the inner key. Throws when the key has already been
    /// consumed via <see cref="UseKey"/> or the wrapper has been disposed.
    /// </summary>
    public Tag Tag
    {
        get
        {
            SymmetricKeyMemory? local = inner;
            if(local is null)
            {
                throw new InvalidOperationException(
                    "Content encryption key has already been used or disposed.");
            }
            return local.Tag;
        }
    }


    /// <summary>
    /// Initialises a new <see cref="ContentEncryptionKey"/> wrapping the supplied
    /// <see cref="SymmetricKeyMemory"/>. Ownership of <paramref name="inner"/>
    /// transfers to this wrapper; the wrapper transfers ownership again on
    /// <see cref="UseKey"/>.
    /// </summary>
    public ContentEncryptionKey(SymmetricKeyMemory inner, System.Diagnostics.Activity? lifetime = null)
    {
        ArgumentNullException.ThrowIfNull(inner);
        this.inner = inner;
        this.lifetime = lifetime;
    }


    /// <summary>
    /// Consumes the wrapper and returns the inner <see cref="SymmetricKeyMemory"/>.
    /// The wrapper becomes empty; a second call throws
    /// <see cref="InvalidOperationException"/>. The caller takes ownership of the
    /// returned key and is responsible for disposing it.
    /// </summary>
    public SymmetricKeyMemory UseKey()
    {
        int count = Interlocked.Increment(ref useCount);
        lifetime?.SetTag(CryptoTelemetry.ContentEncryptionKey.UseCount, count);

        SymmetricKeyMemory? local = Interlocked.Exchange(ref inner, null);
        if(local is null)
        {
            throw new InvalidOperationException(
                "Content encryption key has already been used. CEKs are single-use by "
                + "construction; see ContentEncryptionKey type documentation for the "
                + "rationale and the relationship to Nonce.UseNonce().");
        }
        return local;
    }


    /// <summary>
    /// Disposes the wrapper. If <see cref="UseKey"/> has not been called, the inner
    /// <see cref="SymmetricKeyMemory"/> is disposed here; otherwise this is a no-op.
    /// </summary>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        SymmetricKeyMemory? local = Interlocked.Exchange(ref inner, null);
        local?.Dispose();

        if(lifetime is not null)
        {
            lifetime.SetTag(CryptoTelemetry.ContentEncryptionKey.FinalUseCount, useCount);
            lifetime.Stop();
        }

        disposed = true;
    }
}
