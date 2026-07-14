using System.Buffers;
using System.Diagnostics;

namespace Verifiable.JCose;

/// <summary>
/// A parsed <c>recipients</c> array element from a JWE General JSON Serialization: the
/// recipient's <c>kid</c> and the wrapped CEK bytes (<c>encrypted_key</c>) decoded from
/// base64url.
/// </summary>
/// <remarks>
/// The wrapped key is public ciphertext but is held in pooled memory and cleared on
/// disposal alongside the rest of the parsed message.
/// </remarks>
[DebuggerDisplay("AeadGeneralRecipient KeyId={KeyId} WrappedKeyLength={WrappedKey.Length}")]
public sealed class AeadGeneralRecipient: IDisposable
{
    private IMemoryOwner<byte> WrappedKeyOwner { get; }
    private bool disposed;

    /// <summary>
    /// The recipient's <c>kid</c> from the per-recipient unprotected <c>header</c>.
    /// </summary>
    public string KeyId { get; }

    /// <summary>The wrapped CEK bytes decoded from the <c>encrypted_key</c>.</summary>
    public ReadOnlyMemory<byte> WrappedKey => WrappedKeyOwner.Memory;


    /// <summary>
    /// Initializes an <see cref="AeadGeneralRecipient"/>. Ownership of
    /// <paramref name="wrappedKeyOwner"/> transfers to this instance.
    /// </summary>
    public AeadGeneralRecipient(string keyId, IMemoryOwner<byte> wrappedKeyOwner)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        ArgumentNullException.ThrowIfNull(wrappedKeyOwner);

        KeyId = keyId;
        this.WrappedKeyOwner = wrappedKeyOwner;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            WrappedKeyOwner.Memory.Span.Clear();
            WrappedKeyOwner.Dispose();
            disposed = true;
        }
    }
}
