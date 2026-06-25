using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// The result of verifying an OID4VCI 1.0 Appendix D.1 key attestation (<c>key-attestation+jwt</c>)
/// with <see cref="KeyAttestationVerifier"/>. On success it carries the verified
/// <see cref="KeyAttestation"/> — the attested keys the Issuer may now bind Credentials to; on failure
/// it carries the single <see cref="KeyAttestationVerificationFailureReason"/>.
/// </summary>
/// <remarks>
/// Mint-only: the constructor and factories are <see langword="internal"/>, so a result with
/// <see cref="IsValid"/> <see langword="true"/> can only originate from this library's verification path
/// — application code cannot fabricate a "verified" attestation. This mirrors the JOSE layer's
/// <c>JwsVerificationResult</c> and DIDComm's <c>DidCommSignedVerificationResult</c> trust-carrier
/// pattern (and unlike the structural-only <see cref="KeyAttestationParser"/>, possession of a valid
/// result IS the proof the signature and Wallet-Provider key were checked).
/// </remarks>
[DebuggerDisplay("KeyAttestationVerificationResult Valid={IsValid} Reason={FailureReason}")]
public sealed record KeyAttestationVerificationResult
{
    private KeyAttestationVerificationResult(KeyAttestation? attestation, KeyAttestationVerificationFailureReason? failureReason)
    {
        Attestation = attestation;
        FailureReason = failureReason;
    }


    /// <summary>The verified attestation body when verification succeeded; otherwise <see langword="null"/>.</summary>
    public KeyAttestation? Attestation { get; }

    /// <summary>The reason verification failed; <see langword="null"/> on success.</summary>
    public KeyAttestationVerificationFailureReason? FailureReason { get; }

    /// <summary><see langword="true"/> when the attestation's signature and Wallet-Provider key verified and every check passed.</summary>
    public bool IsValid => FailureReason is null;


    //Mints a verified result carrying the authenticated attestation. Internal so only the library's
    //verification path can produce one.
    internal static KeyAttestationVerificationResult Success(KeyAttestation attestation)
    {
        ArgumentNullException.ThrowIfNull(attestation);

        return new KeyAttestationVerificationResult(attestation, failureReason: null);
    }


    //Mints a failed result carrying the rejection reason and no attestation.
    internal static KeyAttestationVerificationResult Failure(KeyAttestationVerificationFailureReason reason) =>
        new(attestation: null, reason);
}
