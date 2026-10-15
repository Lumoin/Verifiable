namespace Verifiable.Cryptography;

/// <summary>
/// What one signing operation answers (<see cref="SigningDelegate"/>, <see cref="RecoverableSigningDelegate"/>): the
/// signature, in pooled memory the caller owns and disposes, and the <see cref="SignatureProducedEvent"/> describing the
/// operation, or <see langword="null"/> from a function that publishes its event through a seam of its own or supports no
/// observability.
/// </summary>
/// <param name="Signature">The signature, owned by the caller.</param>
/// <param name="Event">The event describing the operation, or <see langword="null"/>.</param>
public sealed record SigningResult(Signature Signature, CryptoEvent? Event);
