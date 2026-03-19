using System.Diagnostics;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// The result of an encrypt-side ECDH key agreement operation: the shared secret Z
/// and the sender's ephemeral public key in uncompressed encoding.
/// </summary>
/// <remarks>
/// <para>
/// Produced by <see cref="KeyAgreementEncryptDelegate"/> and consumed immediately by
/// the key derivation step. The shared secret must be zeroed and disposed as soon as
/// the CEK has been derived. The ephemeral public key is carried forward into the
/// JWE protected header as the <c>epk</c> parameter.
/// </para>
/// <para>
/// The ephemeral public key is stored as an uncompressed EC point:
/// <c>0x04 || X (32 bytes) || Y (32 bytes)</c> for P-256. This is the canonical
/// form used by all EC backends and avoids splitting the point across two separate
/// allocations.
/// </para>
/// <para>
/// This type is disposable because <see cref="SharedSecret"/> is sensitive memory.
/// <see cref="EphemeralPublicKey"/> is a public value but is owned here and disposed
/// alongside the secret.
/// </para>
/// </remarks>
[DebuggerDisplay("EphemeralKeyAgreementResult Curve={EphemeralPublicKey.Tag}")]
public sealed class EphemeralKeyAgreementResult: IDisposable
{
    private bool disposed;

    /// <summary>
    /// The shared secret Z produced by scalar multiplication. Must be zeroed immediately
    /// after the CEK is derived.
    /// </summary>
    public SharedSecret SharedSecret { get; }

    /// <summary>
    /// The sender's ephemeral public key in uncompressed encoding:
    /// <c>0x04 || X || Y</c>. Tagged with the curve-specific tag.
    /// </summary>
    public PublicKeyMemory EphemeralPublicKey { get; }


    /// <summary>
    /// Initializes a new <see cref="EphemeralKeyAgreementResult"/>. Ownership of all
    /// components transfers to this instance.
    /// </summary>
    public EphemeralKeyAgreementResult(
        SharedSecret sharedSecret,
        PublicKeyMemory ephemeralPublicKey)
    {
        ArgumentNullException.ThrowIfNull(sharedSecret);
        ArgumentNullException.ThrowIfNull(ephemeralPublicKey);

        SharedSecret = sharedSecret;
        EphemeralPublicKey = ephemeralPublicKey;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            SharedSecret.Dispose();
            EphemeralPublicKey.Dispose();
            disposed = true;
        }
    }
}
