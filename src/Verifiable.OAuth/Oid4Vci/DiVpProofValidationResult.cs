using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// The discrete reasons one OID4VCI 1.0 Appendix F.2 <c>di_vp</c> key proof — a W3C Verifiable
/// Presentation secured with a Data Integrity proof — can be rejected. The set is closed; the
/// Credential Endpoint maps each to a §8.3.1.2 Credential Error Response code:
/// <see cref="ChallengeMismatch"/> maps to <c>invalid_nonce</c> (the proof's <c>challenge</c> is
/// the server-provided <c>c_nonce</c>, so a stale one is a nonce failure the Wallet recovers from
/// by fetching a fresh nonce), every other reason maps to <c>invalid_proof</c>.
/// </summary>
public enum DiVpProofValidationFailureReason
{
    /// <summary>The <c>di_vp</c> array entry did not parse as a Data Integrity-secured presentation.</summary>
    Unparseable,

    /// <summary>
    /// The holder DID document could not be resolved, so the proof cannot be checked against the
    /// holder's <c>authentication</c> relationship (Appendix F.2: the presentation must be "actually
    /// signed with a key in the possession of the Holder").
    /// </summary>
    HolderUnresolved,

    /// <summary>The presentation carries no Data Integrity proof (Appendix F.2: <c>proof</c> is REQUIRED).</summary>
    NoProof,

    /// <summary>
    /// The proof's <c>proofPurpose</c> is not <c>authentication</c> (Appendix F.2: "proofPurpose:
    /// REQUIRED. MUST be set to authentication").
    /// </summary>
    ProofPurposeMismatch,

    /// <summary>
    /// The proof's <c>challenge</c> does not equal the server-provided <c>c_nonce</c> (Appendix F.2:
    /// "challenge ... where the value is a server-provided c_nonce"). Maps to <c>invalid_nonce</c>.
    /// </summary>
    ChallengeMismatch,

    /// <summary>
    /// The proof's <c>domain</c> does not equal the Credential Issuer Identifier (Appendix F.2:
    /// "domain: REQUIRED. MUST be set to the Credential Issuer Identifier").
    /// </summary>
    DomainMismatch,

    /// <summary>
    /// The verification method the proof names is not in the holder's <c>authentication</c>
    /// relationship, or a required proof member is absent.
    /// </summary>
    VerificationMethodNotFound,

    /// <summary>The presentation's Data Integrity signature does not verify with the holder key.</summary>
    SignatureInvalid,
}


/// <summary>
/// The result of validating one OID4VCI 1.0 Appendix F.2 <c>di_vp</c> key proof. On success it
/// carries the authenticated holder verification method id — the key in the Holder's possession the
/// presentation authenticated, the binding the issued Credential uses (Appendix F.2: the Credential
/// Issuer "MUST validate that the W3C Verifiable Presentation used as a proof is actually signed
/// with a key in the possession of the Holder"). On failure it carries the single
/// <see cref="DiVpProofValidationFailureReason"/> the Credential Endpoint maps to a §8.3.1.2 error.
/// </summary>
[DebuggerDisplay("DiVpProofValidationResult Valid={IsValid} Reason={FailureReason} Holder={AuthenticatedVerificationMethodId,nq}")]
public sealed record DiVpProofValidationResult
{
    /// <summary>
    /// The DID URL of the holder verification method the presentation authenticated, when validation
    /// succeeded. The issued Credential is bound to this key. <see langword="null"/> on failure.
    /// </summary>
    public string? AuthenticatedVerificationMethodId { get; init; }

    /// <summary>The failure reason if the proof was rejected. <see langword="null"/> on success.</summary>
    public DiVpProofValidationFailureReason? FailureReason { get; init; }

    /// <summary><see langword="true"/> when the presentation proof is valid.</summary>
    public bool IsValid => FailureReason is null;

    /// <summary>Builds a success result carrying the authenticated holder verification method id.</summary>
    public static DiVpProofValidationResult Success(string authenticatedVerificationMethodId) =>
        new() { AuthenticatedVerificationMethodId = authenticatedVerificationMethodId };

    /// <summary>Builds a failure result.</summary>
    public static DiVpProofValidationResult Failure(DiVpProofValidationFailureReason reason) =>
        new() { FailureReason = reason };
}
