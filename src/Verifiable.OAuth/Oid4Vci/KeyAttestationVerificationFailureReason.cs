namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// The discrete reasons an OID4VCI 1.0 Appendix D.1 key attestation (<c>key-attestation+jwt</c>) can
/// fail verification by <see cref="KeyAttestationVerifier"/>. The set is closed; new reasons land as
/// additional cases. Every value denotes a rejected attestation whose attested keys MUST NOT be trusted.
/// </summary>
public enum KeyAttestationVerificationFailureReason
{
    /// <summary>The attestation is not parseable as a compact JWS, its <c>typ</c> is not <c>key-attestation+jwt</c>, or the REQUIRED <c>attested_keys</c> array is absent (Appendix D.1).</summary>
    Malformed,

    /// <summary>The attestation has no signature segment — a verifiable attestation MUST be a signed three-part JWS, not the unsigned two-part form.</summary>
    NotSigned,

    /// <summary>The <c>alg</c> header is missing, is <c>none</c>, is a symmetric (MAC) algorithm, or is not acceptable per the application's policy.</summary>
    InvalidAlg,

    /// <summary>The mutually-exclusive <c>jwk</c>/<c>kid</c>/<c>x5c</c> trio names more than one member or none, or the <c>jwk</c> is not a readable public key.</summary>
    InvalidKeyReference,

    /// <summary>The Wallet-Provider key named by <c>kid</c> or <c>x5c</c> could not be dereferenced — no resolver, missing trust material, or a chain that did not validate to the supplied anchors.</summary>
    KeyReferenceUnresolved,

    /// <summary>The attestation's signature does not verify with the resolved Wallet-Provider key.</summary>
    SignatureFailed,

    /// <summary>The attestation's <c>exp</c> is in the past (the attestation and its attested keys have expired) (Appendix D.1).</summary>
    Expired,

    /// <summary>A <c>nonce</c> was required (the Issuer supplied one) but the attestation carries none (Appendix D.1).</summary>
    NonceMissing,

    /// <summary>The attestation's <c>nonce</c> does not equal the Issuer-provided value (Appendix D.1).</summary>
    NonceMismatch
}
