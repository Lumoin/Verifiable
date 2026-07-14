using System;

namespace Verifiable.Cryptography;

/// <summary>
/// Fills <paramref name="destination"/> with bytes from an entropy source.
/// </summary>
/// <param name="destination">
/// The span to fill. The implementation must fill the entire span.
/// </param>
/// <remarks>
/// <para>
/// The implementation decides the entropy source — CSPRNG, TPM, HSM, or
/// deterministic test vector. The caller has no visibility into how the
/// bytes are produced; that information is captured in the accompanying
/// <see cref="EntropyHealthObservation"/> returned alongside the generated value.
/// </para>
/// <para>
/// Production implementations must use a cryptographically strong source.
/// Deterministic implementations (for test reproducibility) must never be
/// registered in production.
/// </para>
/// <para>
/// Common implementations via direct method group:
/// </para>
/// <code>
/// FillEntropyDelegate csprng = RandomNumberGenerator.Fill;
/// FillEntropyDelegate tpm    = tpmEntropyProvider.Fill;
/// </code>
/// </remarks>
public delegate void FillEntropyDelegate(Span<byte> destination);