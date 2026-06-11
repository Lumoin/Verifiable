namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// The discrete reasons an OID4VCI 1.0 <c>jwt</c> key proof can be rejected, per the
/// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-F.4">Appendix F.4</see>
/// proof-validation checks. The set is closed; new reasons land as additional cases. The
/// Credential Endpoint maps each to a §8.3.1.2 Credential Error Response code: the two nonce
/// reasons map to <c>invalid_nonce</c> (the Wallet should retrieve a fresh <c>c_nonce</c>),
/// every other reason maps to <c>invalid_proof</c>.
/// </summary>
public enum CredentialProofValidationFailureReason
{
    /// <summary>The proof string is not parseable as a compact JWS.</summary>
    Malformed,

    /// <summary>
    /// The <c>typ</c> header is missing or is not <c>openid4vci-proof+jwt</c> (§F.1 / §F.4:
    /// "the key proof is explicitly typed using header parameters as defined for that proof type").
    /// </summary>
    InvalidTyp,

    /// <summary>
    /// The <c>alg</c> header is missing, is <c>none</c>, is a symmetric (MAC) algorithm, or is not
    /// among the application-supplied accepted algorithms (§F.1: "It MUST NOT be none or an
    /// identifier for a symmetric algorithm (MAC)"; §F.4: "indicates a registered asymmetric digital
    /// signature algorithm, alg parameter value is not none, is supported by the application, and is
    /// acceptable per local policy").
    /// </summary>
    InvalidAlg,

    /// <summary>
    /// The key reference is malformed: the mutually-exclusive §F.1 trio <c>jwk</c>/<c>kid</c>/<c>x5c</c>
    /// names more than one member, names none, or the <c>jwk</c> is not a readable public key.
    /// </summary>
    InvalidKeyReference,

    /// <summary>
    /// The <c>jwk</c> header carries private or symmetric key material (§F.4: "the header parameter
    /// does not contain a private key").
    /// </summary>
    JwkContainsPrivateKey,

    /// <summary>
    /// The proof names a key via <c>kid</c> or <c>x5c</c> but no key-resolution delegate was supplied
    /// to dereference it. The <c>jwk</c> reference mode is self-contained and needs no resolver; the
    /// other two modes are resolved by the deployment, whose trust anchors live in the application.
    /// </summary>
    KeyReferenceUnresolved,

    /// <summary>
    /// The proof's signature does not verify with the referenced public key (§F.4: "the signature on
    /// the key proof verifies with the public key contained in the header parameter").
    /// </summary>
    SignatureFailed,

    /// <summary>
    /// The <c>aud</c> claim is missing or does not equal the Credential Issuer Identifier (§F.1:
    /// "aud: REQUIRED (string). The value of this claim MUST be the Credential Issuer Identifier").
    /// </summary>
    AudienceMismatch,

    /// <summary>
    /// The <c>iat</c> claim is absent or outside the acceptance window (§F.1: "iat: REQUIRED (number)";
    /// §F.4: "the creation time of the JWT ... is within an acceptable window").
    /// </summary>
    IatOutOfWindow,

    /// <summary>
    /// The <c>nonce</c> claim is absent when the Issuer's Nonce Endpoint supplied a <c>c_nonce</c>
    /// (§F.1: "It MUST be present when the issuer has a Nonce Endpoint"; §F.4: "if the server has a
    /// Nonce Endpoint, the nonce in the key proof matches the server-provided c_nonce value").
    /// Maps to <c>invalid_nonce</c>.
    /// </summary>
    NonceMissing,

    /// <summary>
    /// The <c>nonce</c> claim does not equal the server-provided <c>c_nonce</c> (§F.4: "the nonce in
    /// the key proof matches the server-provided c_nonce value"). Maps to <c>invalid_nonce</c>.
    /// </summary>
    NonceMismatch,
}
