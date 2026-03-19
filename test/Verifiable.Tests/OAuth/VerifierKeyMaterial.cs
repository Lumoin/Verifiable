using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.OAuth.Server;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The key material generated for a single client registration.
/// </summary>
/// <remarks>
/// Returned from <see cref="VerifierServerSetup.RegisterClient"/>. The caller
/// is responsible for disposing after the test — the signing and decryption keys
/// are <see cref="PrivateKeyMemory"/> instances backed by pooled memory.
/// </remarks>
[DebuggerDisplay("VerifierKeyMaterial Segment={Registration.TenantId}")]
internal sealed class VerifierKeyMaterial: IDisposable
{
    private bool disposed;

    /// <summary>The client registration for this key material.</summary>
    public ClientRegistration Registration { get; }

    /// <summary>
    /// The Verifier's public signing key. The Wallet uses this to verify JAR signatures.
    /// </summary>
    public PublicKeyMemory SigningPublicKey { get; }

    /// <summary>The signing private key used to sign JARs.</summary>
    public PrivateKeyMemory SigningPrivateKey { get; }

    /// <summary>The decryption private key used to decrypt direct_post JWE responses.</summary>
    public PrivateKeyMemory DecryptionPrivateKey { get; }

    /// <summary>The key identifier for the decryption key.</summary>
    public KeyId EncryptionKeyId { get; }

    /// <summary>The key identifier for the signing key.</summary>
    public KeyId SigningKeyId { get; }


    /// <summary>
    /// Initializes a new <see cref="VerifierKeyMaterial"/>.
    /// </summary>
    public VerifierKeyMaterial(
        ClientRegistration registration,
        PublicKeyMemory signingPublicKey,
        PrivateKeyMemory signingPrivateKey,
        PrivateKeyMemory decryptionPrivateKey,
        KeyId encryptionKeyId,
        KeyId signingKeyId)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(signingPublicKey);
        ArgumentNullException.ThrowIfNull(signingPrivateKey);
        ArgumentNullException.ThrowIfNull(decryptionPrivateKey);

        Registration = registration;
        SigningPublicKey = signingPublicKey;
        SigningPrivateKey = signingPrivateKey;
        DecryptionPrivateKey = decryptionPrivateKey;
        EncryptionKeyId = encryptionKeyId;
        SigningKeyId = signingKeyId;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        disposed = true;
        SigningPublicKey.Dispose();
        SigningPrivateKey.Dispose();
        DecryptionPrivateKey.Dispose();
    }
}
