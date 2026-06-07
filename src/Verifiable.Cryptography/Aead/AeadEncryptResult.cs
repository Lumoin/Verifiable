using System.Diagnostics;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// The result of an AEAD symmetric encryption operation: initialization vector,
/// ciphertext, and authentication tag.
/// </summary>
/// <remarks>
/// <para>
/// Produced by <see cref="AeadEncryptDelegate"/> and combined with the ephemeral
/// public key coordinates from <see cref="EphemeralKeyAgreementResult"/> to form
/// the complete encrypted message. All components are disposable pooled memory.
/// </para>
/// </remarks>
[DebuggerDisplay("AeadEncryptResult CiphertextLength={Ciphertext.Length}")]
public sealed class AeadEncryptResult: IDisposable
{
    private bool disposed;

    /// <summary>The initialization vector nonce. Unique per encryption operation.</summary>
    public Nonce Iv { get; }

    /// <summary>The ciphertext bytes produced by content encryption.</summary>
    public Ciphertext Ciphertext { get; }

    /// <summary>
    /// The authentication tag. For AES-GCM this is GHASH output — a MAC, not an HMAC.
    /// </summary>
    public AuthenticationTag Tag { get; }


    /// <summary>
    /// Initializes a new <see cref="AeadEncryptResult"/>. Ownership of all components
    /// transfers to this instance.
    /// </summary>
    public AeadEncryptResult(Nonce iv, Ciphertext ciphertext, AuthenticationTag tag)
    {
        ArgumentNullException.ThrowIfNull(iv);
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(tag);

        Iv = iv;
        Ciphertext = ciphertext;
        Tag = tag;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            Iv.Dispose();
            Ciphertext.Dispose();
            Tag.Dispose();
            disposed = true;
        }
    }
}
