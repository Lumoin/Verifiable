using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Cryptography;

/// <summary>
/// A wrapper for private key memory that has the capability to unwrap the data
/// during private key operations.
/// </summary>
/// <remarks>
/// If counters, statistics, or other functionality is needed this class can be inherited,
/// following the same pattern as <see cref="PublicKeyMemory"/>.
/// </remarks>
[DebuggerDisplay("PrivateKeyMemory Algorithm={Tag.Get<Verifiable.Cryptography.Context.CryptoAlgorithm>()} Purpose={Tag.Get<Verifiable.Cryptography.Context.Purpose>()}")]
public class PrivateKeyMemory: SensitiveMemory
{
    /// <summary>
    /// Initializes a new <see cref="PrivateKeyMemory"/> from owned memory.
    /// </summary>
    /// <param name="memory">The owned memory containing the private key bytes.</param>
    /// <param name="tag">
    /// Metadata identifying the algorithm, purpose, and encoding of the key.
    /// </param>
    /// <param name="lifetime">
    /// Optional OTel activity spanning this key's lifetime. Pass <see langword="null"/>
    /// when no OTel listener is active.
    /// </param>
    public PrivateKeyMemory(IMemoryOwner<byte> memory, Tag tag, Activity? lifetime = null)
        : base(memory, tag, lifetime)
    {
        ArgumentNullException.ThrowIfNull(memory);
        ArgumentNullException.ThrowIfNull(tag);
    }


    /// <summary>
    /// Passes the private key bytes to <paramref name="operation"/> and returns the result.
    /// </summary>
    /// <remarks>
    /// The key bytes are exposed only for the duration of the delegate call. They remain
    /// owned and protected by this instance throughout. Nothing is captured by closure —
    /// all needed state must be passed via <paramref name="dataToSign"/> and
    /// <paramref name="signaturePool"/>.
    /// </remarks>
    /// <typeparam name="TDataToSign">The element type of the data to sign, typically <see cref="byte"/>.</typeparam>
    /// <typeparam name="TResult">The result type, typically <see cref="System.Threading.Tasks.ValueTask{Signature}"/>.</typeparam>
    /// <param name="operation">
    /// The signing delegate to invoke with the key bytes. Must not store a reference to the memory.
    /// </param>
    /// <param name="dataToSign">The data to sign, passed through to the operation.</param>
    /// <param name="signaturePool">The memory pool for allocating the signature, passed through to the operation.</param>
    /// <returns>The result produced by <paramref name="operation"/>.</returns>
    public TResult WithKeyBytesAsync<TDataToSign, TResult>(
        SigningFunction<byte, TDataToSign, TResult> operation,
        ReadOnlyMemory<TDataToSign> dataToSign,
        MemoryPool<byte> signaturePool)
    {
        ArgumentNullException.ThrowIfNull(operation);
        return operation(MemoryOwner.Memory, dataToSign, signaturePool);
    }


    /// <summary>
    /// Passes the private key bytes to <paramref name="operation"/> and returns the result.
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