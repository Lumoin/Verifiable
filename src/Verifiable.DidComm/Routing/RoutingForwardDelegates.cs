using System.Buffers;

namespace Verifiable.DidComm.Routing;

/// <summary>
/// Produces a fresh ephemeral key pair for one forward-wrapping hop — a new X25519 key pair the
/// anoncrypt <c>epk</c> is drawn from, of the same type and curve as the routing key it encrypts for
/// (DIDComm v2.1 §ECDH-ES key wrapping). A distinct ephemeral key is used per hop and disposed after it.
/// </summary>
/// <param name="memoryPool">The pool the key material is drawn from.</param>
/// <returns>The ephemeral public/private key pair. The caller disposes both halves.</returns>
public delegate Verifiable.Cryptography.PublicPrivateKeyMaterial<Verifiable.Cryptography.PublicKeyMemory, Verifiable.Cryptography.PrivateKeyMemory> EphemeralKeyPairFactory(MemoryPool<byte> memoryPool);
