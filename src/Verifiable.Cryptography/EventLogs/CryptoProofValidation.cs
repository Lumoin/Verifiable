using System;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography.EventLogs;

/// <summary>
/// Builds the <see cref="ValidateProofDelegate{TState,TOperation,TProof,TContext}"/> for logs whose proofs are
/// generic <see cref="CryptoProof"/> values.
/// </summary>
/// <remarks>
/// <para>
/// This is the domain-agnostic proof-verification path: it resolves the verification function for each proof's
/// <see cref="CryptoProof.Algorithm"/> from <c>CryptoFunctionRegistry</c> — the same seam the library uses for
/// X.509, DID, and mdoc signatures — and checks the signature over the entry's
/// <see cref="LogEntry{TOperation,TProof}.CanonicalBytes"/>. A TPM quote whose signature and attestation key
/// have been projected into <see cref="Signature"/> and <see cref="PublicKeyMemory"/> verifies here with no
/// TPM-specific code.
/// </para>
/// <para>
/// Establishing trust in each signer key — a certificate chain to an anchor, revocation status, a DID-document
/// binding — is a separate concern layered on by the caller's validation context; this delegate verifies only
/// that the carried signatures are valid over the signed bytes. It is fail-closed: every carried proof must
/// verify, and an entry with no proof is rejected.
/// </para>
/// </remarks>
public static class CryptoProofValidation
{
    /// <summary>
    /// Creates a proof-validation delegate that requires every <see cref="CryptoProof"/> carried by an entry to
    /// verify over the entry's canonical bytes (unanimity). Callers needing a quorum or signer-set policy wrap
    /// this or supply their own delegate.
    /// </summary>
    /// <typeparam name="TState">The domain state type.</typeparam>
    /// <typeparam name="TOperation">The domain operation type.</typeparam>
    /// <typeparam name="TContext">The caller-defined validation context type; unused by signature verification but carried for composition.</typeparam>
    /// <returns>A proof-validation delegate for <see cref="CryptoProof"/> entries.</returns>
    public static ValidateProofDelegate<TState, TOperation, CryptoProof, TContext> CreateValidateProof<TState, TOperation, TContext>()
    {
        return async (entry, currentState, validationContext, cancellationToken) =>
        {
            ArgumentNullException.ThrowIfNull(entry);

            if(entry.Proofs.IsDefaultOrEmpty)
            {
                return "The log entry carries no cryptographic proof.";
            }

            for(int proofIndex = 0; proofIndex < entry.Proofs.Length; proofIndex++)
            {
                CryptoProof proof = entry.Proofs[proofIndex];
                VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(
                    proof.Algorithm, Purpose.Verification);

                bool verified = await verify(
                    entry.CanonicalBytes, proof.Signature.AsReadOnlyMemory(), proof.SignerKey.AsReadOnlyMemory(), null, cancellationToken).ConfigureAwait(false);

                if(!verified)
                {
                    return $"The cryptographic proof at index {proofIndex} ({proof.Algorithm}) does not verify over the entry's canonical bytes.";
                }
            }

            return null;
        };
    }
}
