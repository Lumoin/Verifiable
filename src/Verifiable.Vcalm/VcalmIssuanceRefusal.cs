namespace Verifiable.Vcalm;

/// <summary>
/// Why a VCALM 1.0 §3.2.1 issuance refused its input before signing anything, carried on
/// <see cref="VcalmIssuanceResult.Refusal"/> so the issuing endpoint and the exchange workflow engine report the same
/// refusal for the same input.
/// </summary>
public enum VcalmIssuanceRefusal
{
    /// <summary>Nothing was refused: the credential was secured.</summary>
    None,

    /// <summary>
    /// §3.2.1 Error Handling: the instance is configured to only accept credentials without existing proofs
    /// (<see cref="VcalmExistingProofHandling.Error"/>) and the input carried one.
    /// </summary>
    ExistingProofRejected,

    /// <summary>
    /// An existing proof lacks <c>type</c>, <c>verificationMethod</c> or <c>proofPurpose</c>, which
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see> requires of every
    /// proof, so no new proof is placed beside it in a proof set or chained onto it in a proof chain.
    /// </summary>
    IncompleteExistingProof
}
