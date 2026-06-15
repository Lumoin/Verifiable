namespace Verifiable.Vcalm;

/// <summary>
/// How a VCALM 1.0 §3.2.1 issuer instance handles a provided credential that already carries one or
/// more proofs. §3.2.1: "If a provided credential already contains one or more proofs, the behavior
/// is determined by the configuration of the issuer instance. An issuing instance SHOULD be
/// configured to handle existing proofs in one of the following ways: Proof Sets … Proof Chains …
/// Error Handling".
/// </summary>
/// <remarks>
/// <para>
/// The instance carries one value on <see cref="VcalmCredentialIssuance.ExistingProofHandling"/>;
/// the value governs ONLY the caller-supplied existing-proof case. The §3.2.1 multi-proof
/// requirement ("if multiple proofs are needed, the instance MUST attach all of these proofs in
/// response to a single call") is a separate concern realized by the instance's
/// <see cref="VcalmCredentialIssuance.SigningDescriptors"/> carrying one-or-more proof descriptors.
/// </para>
/// <para>
/// <see cref="ProofChain"/> is the value that round-trips through the W3C VC Data Integrity §2.1.2
/// proof-chain verifier (each appended proof's <c>previousProof</c> references the prior proof's
/// <c>id</c>, the form <c>CredentialDataIntegrityExtensions.SignAsync</c> produces and
/// <c>CredentialDataIntegrityExtensions.VerifyAsync</c> walks). <see cref="ProofSet"/> appends
/// parallel proofs with no chain link per §2.1.1; the Data Integrity verifier currently walks proof
/// chains only, so a set's verification round-trip is the §3.2.1 issuer concern, not a §3.3 verifier
/// guarantee.
/// </para>
/// </remarks>
public enum VcalmExistingProofHandling
{
    /// <summary>
    /// §3.2.1 Error Handling: "Return an error if credential values that contain existing proof
    /// values are provided, when the instance is configured to only accept credentials without
    /// existing proofs." The §3.2.1 400 case. The default — an instance that has not opted into
    /// appending proofs over caller-supplied ones rejects them rather than silently dropping or
    /// re-securing them.
    /// </summary>
    Error = 0,

    /// <summary>
    /// §3.2.1 Proof Sets: "Append new proofs to the list of existing proofs provided by the caller,
    /// first converting any existing single proof to a list if necessary. Here there is no binding
    /// to any existing proofs; the new proofs exist in parallel with those previously provided by
    /// the caller." The appended proofs carry no <c>previousProof</c> link.
    /// </summary>
    ProofSet,

    /// <summary>
    /// §3.2.1 Proof Chains: "Append new proofs to create or extend an existing proof chain. Here
    /// proofs are linked in a specific sequence, … using the previousProof property to establish the
    /// chain relationship." Each appended proof's <c>previousProof</c> references the last existing
    /// proof's <c>id</c> (W3C VC Data Integrity §2.1.2).
    /// </summary>
    ProofChain
}
