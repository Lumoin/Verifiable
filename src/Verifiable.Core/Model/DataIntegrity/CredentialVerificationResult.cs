using System.Diagnostics;

namespace Verifiable.Core.Model.DataIntegrity;


/// <summary>
/// Enumerates the possible reasons for credential verification failure.
/// </summary>
public enum VerificationFailureReason
{
    /// <summary>
    /// No failure; verification succeeded.
    /// </summary>
    None = 0,

    /// <summary>
    /// The credential has no proof attached.
    /// </summary>
    NoProof,

    /// <summary>
    /// The proof is missing the cryptosuite specification.
    /// </summary>
    MissingCryptosuite,

    /// <summary>
    /// The proof is missing the verification method reference.
    /// </summary>
    MissingVerificationMethod,

    /// <summary>
    /// The verification method referenced by the proof was not found in the issuer's DID document.
    /// </summary>
    VerificationMethodNotFound,

    /// <summary>
    /// The cryptographic signature is invalid.
    /// </summary>
    SignatureInvalid,

    /// <summary>
    /// The challenge in the proof does not match the expected challenge issued by the verifier.
    /// </summary>
    ChallengeMismatch,

    /// <summary>
    /// The domain in the proof does not match the expected domain of the verifier.
    /// </summary>
    DomainMismatch,

    /// <summary>
    /// A proof in a proof chain references a previous proof that is missing or unresolved,
    /// or the chain is otherwise not a valid dependency order.
    /// </summary>
    BrokenProofChain,

    /// <summary>
    /// A proof chain contains a cycle in its <c>previousProof</c> references.
    /// </summary>
    ProofChainCycle,

    /// <summary>
    /// The proof's <c>proofPurpose</c> does not match the purpose the verifier expects
    /// for the document class — e.g. a presentation proof whose purpose is not
    /// <c>authentication</c>. Mandated by
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity 1.0
    /// §4.2 Verify Proof</see>: when an expected proof purpose is given and does not match,
    /// an error MUST be raised.
    /// </summary>
    ProofPurposeMismatch
}


/// <summary>
/// Represents the result of verifying a Verifiable Credential's proof.
/// </summary>
/// <remarks>
/// <para>
/// This result indicates whether the cryptographic signature verified successfully.
/// Temporal policy decisions (e.g., "is this credential expired") are the caller's
/// responsibility - they can read <c>ValidFrom</c>, <c>ValidUntil</c>, and proof
/// timestamps directly from the credential they already have.
/// </para>
/// </remarks>
[DebuggerDisplay("{ToString()}")]
public readonly record struct CredentialVerificationResult
{
    /// <summary>
    /// Gets a value indicating whether the credential's cryptographic signature is valid.
    /// </summary>
    public bool IsValid { get; init; }

    /// <summary>
    /// Gets the reason for verification failure, if any.
    /// </summary>
    public VerificationFailureReason FailureReason { get; init; }


    /// <summary>
    /// Creates a successful verification result.
    /// </summary>
    /// <returns>A successful verification result.</returns>
    public static CredentialVerificationResult Success() => new()
    {
        IsValid = true,
        FailureReason = VerificationFailureReason.None
    };


    /// <summary>
    /// Creates a failed verification result with the specified reason.
    /// </summary>
    /// <param name="reason">The reason for verification failure.</param>
    /// <returns>A failed verification result.</returns>
    public static CredentialVerificationResult Failed(VerificationFailureReason reason) => new()
    {
        IsValid = false,
        FailureReason = reason
    };


    /// <summary>
    /// Returns a string representation of the verification result.
    /// </summary>
    /// <returns>A string describing the verification result.</returns>
    public override string ToString() => IsValid ? "Valid" : $"Invalid ({FailureReason})";
}
