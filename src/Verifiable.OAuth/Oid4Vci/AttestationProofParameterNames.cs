using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// Parameter and value NAMES for OID4VCI 1.0 key attestations (Appendix D): the
/// <c>attestation</c> proof type and the <c>key_attestation</c> JOSE header that carry a
/// <c>key-attestation+jwt</c>, its body members (<c>attested_keys</c>, <c>key_storage</c>,
/// <c>user_authentication</c>, <c>certification</c>), and the
/// <c>key_attestations_required</c> metadata flag.
/// </summary>
public static class AttestationProofParameterNames
{
    /// <summary>The UTF-8 source literal of <see cref="AttestationProofType"/>.</summary>
    public static ReadOnlySpan<byte> AttestationProofTypeUtf8 => "attestation"u8;

    /// <summary>
    /// The <c>attestation</c> proof type — a member of the §8.2 <c>proofs</c> object whose value
    /// is an array containing exactly one <c>key-attestation+jwt</c> standing alone (no separate
    /// key proof).
    /// </summary>
    public static readonly string AttestationProofType = Utf8Constants.ToInternedString(AttestationProofTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="KeyAttestation"/>.</summary>
    public static ReadOnlySpan<byte> KeyAttestationUtf8 => "key_attestation"u8;

    /// <summary>
    /// The <c>key_attestation</c> JOSE header (Appendix D / §F.2) carried on a <c>jwt</c> key
    /// proof, conveying a <c>key-attestation+jwt</c> for the key the proof possesses.
    /// </summary>
    public static readonly string KeyAttestation = Utf8Constants.ToInternedString(KeyAttestationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="KeyAttestationJwtType"/>.</summary>
    public static ReadOnlySpan<byte> KeyAttestationJwtTypeUtf8 => "key-attestation+jwt"u8;

    /// <summary>The REQUIRED <c>typ</c> header value of a key attestation JWT (Appendix D.1).</summary>
    public static readonly string KeyAttestationJwtType = Utf8Constants.ToInternedString(KeyAttestationJwtTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AttestedKeys"/>.</summary>
    public static ReadOnlySpan<byte> AttestedKeysUtf8 => "attested_keys"u8;

    /// <summary>
    /// <c>attested_keys</c> — REQUIRED (Appendix D.1). A non-empty array of attested public keys
    /// (JWK syntax) from the same key storage component.
    /// </summary>
    public static readonly string AttestedKeys = Utf8Constants.ToInternedString(AttestedKeysUtf8);

    /// <summary>The UTF-8 source literal of <see cref="KeyStorage"/>.</summary>
    public static ReadOnlySpan<byte> KeyStorageUtf8 => "key_storage"u8;

    /// <summary>
    /// <c>key_storage</c> — OPTIONAL (Appendix D.1/D.2). A non-empty array asserting the attack
    /// potential resistance of the key storage component.
    /// </summary>
    public static readonly string KeyStorage = Utf8Constants.ToInternedString(KeyStorageUtf8);

    /// <summary>The UTF-8 source literal of <see cref="UserAuthentication"/>.</summary>
    public static ReadOnlySpan<byte> UserAuthenticationUtf8 => "user_authentication"u8;

    /// <summary>
    /// <c>user_authentication</c> — OPTIONAL (Appendix D.1/D.2). A non-empty array asserting the
    /// attack potential resistance of the user-authentication methods guarding the attested keys.
    /// </summary>
    public static readonly string UserAuthentication = Utf8Constants.ToInternedString(UserAuthenticationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Certification"/>.</summary>
    public static ReadOnlySpan<byte> CertificationUtf8 => "certification"u8;

    /// <summary><c>certification</c> — OPTIONAL (Appendix D.1). A URL to the key storage component's certification.</summary>
    public static readonly string Certification = Utf8Constants.ToInternedString(CertificationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="KeyAttestationsRequired"/>.</summary>
    public static ReadOnlySpan<byte> KeyAttestationsRequiredUtf8 => "key_attestations_required"u8;

    /// <summary>
    /// <c>key_attestations_required</c> — OPTIONAL (§12.2.4), a member inside a configuration's
    /// <c>proof_types_supported</c> entry. Its PRESENCE signals the Issuer requires a key
    /// attestation for that proof type; its object may carry <c>key_storage</c> /
    /// <c>user_authentication</c> constraints, or be empty.
    /// </summary>
    public static readonly string KeyAttestationsRequired = Utf8Constants.ToInternedString(KeyAttestationsRequiredUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ProofTypesSupported"/>.</summary>
    public static ReadOnlySpan<byte> ProofTypesSupportedUtf8 => "proof_types_supported"u8;

    /// <summary>
    /// <c>proof_types_supported</c> — OPTIONAL (§12.2.4), a member inside a credential
    /// configuration object mapping each supported proof type to its constraints (including
    /// <see cref="KeyAttestationsRequired"/>).
    /// </summary>
    public static readonly string ProofTypesSupported = Utf8Constants.ToInternedString(ProofTypesSupportedUtf8);
}
