using System;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Core.EventLogs;

/// <summary>
/// A generic cryptographic proof for an authenticated log entry: a <see cref="Signature"/> produced by the
/// <see cref="SignerKey"/> public key under the named <see cref="Algorithm"/>, over the entry's
/// <see cref="LogEntry{TOperation,TProof}.CanonicalBytes"/>.
/// </summary>
/// <remarks>
/// <para>
/// This is the neutral, domain-agnostic proof shape that lets attestations from different trust domains —
/// X.509, DID, TPM, AdES — share one <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/> path: each
/// domain reduces its signature and signer to the <c>Verifiable.Cryptography</c> carriers carried here, and
/// <see cref="CryptoProofValidation"/> verifies them through the same <c>CryptoFunctionRegistry</c> seam the rest
/// of the library uses. A TPM quote, for example, becomes a <see cref="CryptoProof"/> by projecting its TPM
/// signature union and attestation-key point into a <see cref="Signature"/> and a <see cref="PublicKeyMemory"/>.
/// </para>
/// <para>
/// This proof <b>references</b> the signature and key carriers; it does not own them. The caller that creates the
/// carriers owns their lifetime and disposes them after replay. Trust in <see cref="SignerKey"/> itself — a
/// certificate chain to an anchor, a DID-document binding, a TPM endorsement-key credential — is established
/// separately (typically through the replay validation context), not by this proof.
/// </para>
/// </remarks>
public sealed class CryptoProof
{
    /// <summary>
    /// Initializes a new cryptographic proof.
    /// </summary>
    /// <param name="signature">The signature over the entry's canonical bytes.</param>
    /// <param name="signerKey">The public key that produced <paramref name="signature"/>.</param>
    /// <param name="algorithm">The algorithm used to resolve the verification function for the proof.</param>
    public CryptoProof(Signature signature, PublicKeyMemory signerKey, CryptoAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(signerKey);

        Signature = signature;
        SignerKey = signerKey;
        Algorithm = algorithm;
    }

    /// <summary>
    /// Gets the signature over the entry's canonical bytes.
    /// </summary>
    public Signature Signature { get; }

    /// <summary>
    /// Gets the public key that produced <see cref="Signature"/>.
    /// </summary>
    public PublicKeyMemory SignerKey { get; }

    /// <summary>
    /// Gets the algorithm used to resolve the verification function for this proof.
    /// </summary>
    public CryptoAlgorithm Algorithm { get; }
}
