namespace Verifiable.Fido2;

/// <summary>
/// The standard <see cref="Fido2AttestationError"/> conditions an attestation statement
/// verification procedure can end in, each exposed as a shared instance. Getters (not
/// <c>static readonly</c> fields) per the codebase convention for shared well-known values.
/// </summary>
public static class Fido2AttestationErrors
{
    /// <summary>
    /// The attestation statement is not valid CBOR conforming to its format's defined syntax, or
    /// omits a mandatory field.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">W3C Web Authentication Level 3, section 8.2: Packed Attestation Statement Format.</see>
    /// Verification procedure step 1: "Verify that attStmt is valid CBOR conforming to the
    /// syntax defined above and perform CBOR decoding on it to extract the contained fields."
    /// </remarks>
    public static Fido2AttestationError MalformedStatement { get; } = new(
        "malformed_statement",
        "The attestation statement is not valid CBOR conforming to its format's defined syntax.");

    /// <summary>
    /// The <c>none</c> attestation statement was not the empty CBOR map its format requires.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-none-attestation">W3C Web Authentication Level 3, section 8.7: None Attestation Statement Format.</see>
    /// </remarks>
    public static Fido2AttestationError StatementNotEmpty { get; } = new(
        "statement_not_empty",
        "The none attestation statement was not the empty CBOR map its format requires.");

    /// <summary>
    /// The authenticator data carries no attested credential data, but the verification
    /// procedure requires it — for example to compare an attestation certificate's AAGUID
    /// extension, or to build the self attestation verification key.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">W3C Web Authentication Level 3, section 6.5.1: Attested Credential Data.</see>
    /// </remarks>
    public static Fido2AttestationError MissingAttestedCredentialData { get; } = new(
        "missing_attested_credential_data",
        "The authenticator data carries no attested credential data, which this verification step requires.");

    /// <summary>
    /// The attestation statement's algorithm does not match the key it is claimed to be signed
    /// with — the credential public key for self attestation, or the attestation certificate's
    /// key for a certified attestation.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">W3C Web Authentication Level 3, section 8.2: Packed Attestation Statement Format.</see>
    /// "Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData."
    /// </remarks>
    public static Fido2AttestationError AlgorithmMismatch { get; } = new(
        "algorithm_mismatch",
        "The attestation statement's algorithm does not match the key it is claimed to be signed with.");

    /// <summary>
    /// The attestation signature did not verify against the concatenation of the authenticator
    /// data and the client data hash.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">W3C Web Authentication Level 3, section 8.2: Packed Attestation Statement Format.</see>
    /// "Verify that sig is a valid signature over the concatenation of authenticatorData and
    /// clientDataHash."
    /// </remarks>
    public static Fido2AttestationError InvalidSignature { get; } = new(
        "invalid_signature",
        "The attestation signature did not verify against the concatenation of the authenticator data and the client data hash.");

    /// <summary>
    /// The attestation statement conveys a certificate path, but no trust anchors were supplied
    /// against which to validate it.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web Authentication Level 3, section 7.1: Registering a New Credential.</see>
    /// Step 23: "obtain a list of acceptable trust anchors (i.e. attestation root certificates)
    /// for that attestation type and attestation statement format fmt".
    /// </remarks>
    public static Fido2AttestationError NoTrustAnchors { get; } = new(
        "no_trust_anchors",
        "The attestation statement conveys a certificate path, but no trust anchors were supplied to validate it against.");

    /// <summary>
    /// The attestation certificate path did not validate against the supplied trust anchors.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web Authentication Level 3, section 7.1: Registering a New Credential.</see>
    /// Step 24: "use the X.509 certificates returned as the attestation trust path from the
    /// verification procedure to verify that the attestation public key either correctly chains
    /// up to an acceptable root certificate, or is itself an acceptable certificate".
    /// </remarks>
    public static Fido2AttestationError ChainValidationFailed { get; } = new(
        "chain_validation_failed",
        "The attestation certificate path did not validate against the supplied trust anchors.");

    /// <summary>
    /// The attestation certificate does not conform to the required certificate profile —
    /// its version, Subject Organizational Unit, Basic Constraints, or an included AAGUID
    /// extension's criticality.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements">W3C Web Authentication Level 3, section 8.2.1: Certificate Requirements for Packed Attestation Statements.</see>
    /// </remarks>
    public static Fido2AttestationError CertificateProfileViolation { get; } = new(
        "certificate_profile_violation",
        "The attestation certificate does not conform to the required certificate profile.");

    /// <summary>
    /// The attestation certificate's AAGUID extension value does not match the AAGUID in the
    /// authenticator data's attested credential data.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements">W3C Web Authentication Level 3, section 8.2.1: Certificate Requirements for Packed Attestation Statements.</see>
    /// "Relying Parties check if the extension is present, and if it is, then validate that it
    /// contains that same AAGUID as presented in the attestation object."
    /// </remarks>
    public static Fido2AttestationError AaguidMismatch { get; } = new(
        "aaguid_mismatch",
        "The attestation certificate's AAGUID extension does not match the AAGUID in the attested credential data.");

    /// <summary>
    /// The attestation certificate does not carry the android key attestation certificate extension
    /// (OID <c>1.3.6.1.4.1.11129.2.1.17</c>) the android-key format requires.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-key-attstn-cert-requirements">W3C Web Authentication Level 3, section 8.4.1: Android Key Attestation Statement Certificate Requirements.</see>
    /// "Android Key Attestation attestation certificate's android key attestation certificate extension
    /// data is identified by the OID 1.3.6.1.4.1.11129.2.1.17."
    /// </remarks>
    public static Fido2AttestationError KeyDescriptionMissing { get; } = new(
        "missing_key_description",
        "The attestation certificate does not carry the android key attestation certificate extension.");

    /// <summary>
    /// The <c>attestationChallenge</c> field in the attestation certificate's key description
    /// extension does not match the client data hash.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation">W3C Web Authentication Level 3, section 8.4: Android Key Attestation Statement Format.</see>
    /// "Verify that the attestationChallenge field in the attestation certificate extension data is
    /// identical to clientDataHash."
    /// </remarks>
    public static Fido2AttestationError AttestationChallengeMismatch { get; } = new(
        "attestation_challenge_mismatch",
        "The attestationChallenge field in the attestation certificate's key description extension does not match the client data hash.");

    /// <summary>
    /// The public key in the first certificate in <c>x5c</c> does not match the
    /// <c>credentialPublicKey</c> in the authenticator data's attested credential data.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation">W3C Web Authentication Level 3, section 8.4: Android Key Attestation Statement Format.</see>
    /// "Verify that the public key in the first certificate in x5c matches the credentialPublicKey in
    /// the attestedCredentialData in authenticatorData."
    /// </remarks>
    public static Fido2AttestationError CredentialKeyMismatch { get; } = new(
        "credential_key_mismatch",
        "The public key in the first certificate in x5c does not match the credentialPublicKey in the attested credential data.");

    /// <summary>
    /// The attestation certificate's key description extension carries an <c>allApplications</c>
    /// field on one of its authorization lists, meaning the key is not scoped to a single RP ID.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation">W3C Web Authentication Level 3, section 8.4: Android Key Attestation Statement Format.</see>
    /// "The AuthorizationList.allApplications field is not present on either authorization list
    /// (softwareEnforced nor teeEnforced), since PublicKeyCredential MUST be scoped to the RP ID."
    /// </remarks>
    public static Fido2AttestationError KeyScopedToAllApplications { get; } = new(
        "key_scoped_to_all_applications",
        "The attestation certificate's key description extension declares the key scoped to all applications, not to a single RP ID.");

    /// <summary>
    /// The applicable authorization list's <c>origin</c> field is not <c>KM_ORIGIN_GENERATED</c>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation">W3C Web Authentication Level 3, section 8.4: Android Key Attestation Statement Format.</see>
    /// "The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED."
    /// </remarks>
    public static Fido2AttestationError KeyOriginNotGenerated { get; } = new(
        "key_origin_not_generated",
        "The applicable authorization list's origin field is not KM_ORIGIN_GENERATED.");

    /// <summary>
    /// The applicable authorization list's <c>purpose</c> field does not contain
    /// <c>KM_PURPOSE_SIGN</c>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation">W3C Web Authentication Level 3, section 8.4: Android Key Attestation Statement Format.</see>
    /// "The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN."
    /// </remarks>
    public static Fido2AttestationError KeyPurposeNotSign { get; } = new(
        "key_purpose_not_sign",
        "The applicable authorization list's purpose field does not contain KM_PURPOSE_SIGN.");

    /// <summary>
    /// The public key in the fido-u2f attestation certificate is not an Elliptic Curve public key
    /// over the P-256 curve.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation">W3C Web Authentication Level 3, section 8.6: FIDO U2F Attestation Statement Format.</see>
    /// "If certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve,
    /// terminate this algorithm and return an appropriate error."
    /// </remarks>
    public static Fido2AttestationError AttestationCertificateKeyNotP256 { get; } = new(
        "attestation_certificate_key_not_p256",
        "The public key in the attestation certificate is not an Elliptic Curve public key over the P-256 curve.");

    /// <summary>
    /// The <c>credentialPublicKey</c>'s <c>x</c> or <c>y</c> coordinate is missing or is not exactly
    /// 32 bytes.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation">W3C Web Authentication Level 3, section 8.6: FIDO U2F Attestation Statement Format.</see>
    /// "Let x be the value corresponding to the "-2" key (representing x coordinate) in
    /// credentialPublicKey, and confirm its size to be of 32 bytes. If size differs or "-2" key is not
    /// found, terminate this algorithm and return an appropriate error." — and symmetrically for the
    /// "-3" key / y.
    /// </remarks>
    public static Fido2AttestationError CredentialCoordinateLengthInvalid { get; } = new(
        "credential_coordinate_length_invalid",
        "The credentialPublicKey's x or y coordinate is missing or is not exactly 32 bytes.");

    /// <summary>
    /// No attestation statement format verification procedure is registered for the attestation
    /// object's <c>fmt</c> value.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web Authentication Level 3, section 7.1: Registering a New Credential.</see>
    /// Step 21: "Determine the attestation statement format by performing a USASCII case-sensitive
    /// match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier
    /// values." An unmatched <c>fmt</c> is untrusted wire input, not a caller configuration
    /// mistake, so it is reported as a rejection rather than thrown.
    /// </remarks>
    public static Fido2AttestationError UnregisteredFormat { get; } = new(
        "unregistered_format",
        "No attestation statement format verification procedure is registered for the given fmt value.");

    /// <summary>
    /// An unexpected error occurred while verifying the attestation statement, outside the
    /// specific failure conditions the format's own verification procedure detects.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-defined-attestation-formats">W3C Web Authentication Level 3, section 8: Defined Attestation Statement Formats.</see>
    /// A registered <see cref="AttestationVerifyDelegate"/> is expected to report a
    /// non-conforming attestation statement as a <see cref="RejectedAttestationResult"/> rather
    /// than throwing; this value is the fail-closed backstop <see cref="Fido2RegistrationVerifier"/>
    /// applies if one throws anyway.
    /// </remarks>
    public static Fido2AttestationError VerificationFailed { get; } = new(
        "verification_failed",
        "An unexpected error occurred while verifying the attestation statement.");

    /// <summary>
    /// The packed attestation certificate carries the enterprise attestation serial-number
    /// extension (OID <c>1.3.6.1.4.1.45724.1.1.2</c>, <c>id-fido-gen-ce-sernum</c>), but the
    /// registration ceremony did not request enterprise attestation.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-enterprise-packed-attestation-cert-requirements">W3C
    /// Web Authentication Level 3, section 8.2.2: Certificate Requirements for Enterprise Packed
    /// Attestation Statements.</see> "This extension MUST NOT be present in non-enterprise
    /// attestations." The CR phrases section 8.2.2 as a constraint on what the authenticator's
    /// certificate is allowed to contain, not as a numbered step of the relying party's own
    /// verification procedure (which never references section 8.2.2) — this rejection is this
    /// codebase's own hardening posture applying that constraint at verification time, following
    /// the AAGUID extension's precedent (<see cref="CertificateProfileViolation"/>).
    /// </remarks>
    public static Fido2AttestationError SerialNumberExtensionNotPermitted { get; } = new(
        "serial_number_extension_not_permitted",
        "The attestation certificate carries the enterprise attestation serial-number extension, but the registration ceremony did not request enterprise attestation.");

    /// <summary>
    /// The attestation statement's <c>alg</c>, or a TPM public area's <c>nameAlg</c>, is not an
    /// algorithm identifier this verification procedure supports.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">W3C Web Authentication Level 3, section 8.3: TPM Attestation Statement Format.</see>
    /// The signing procedure sets <c>extraData</c> "to the digest of attToBeSigned using the hash
    /// algorithm corresponding to the 'alg' signature algorithm"; a TPM public area's Name is
    /// computed "using the nameAlg in the pubArea." An <c>alg</c> or <c>nameAlg</c> this library has
    /// no registered hash for cannot be checked, so it is rejected rather than silently skipped.
    /// </remarks>
    public static Fido2AttestationError UnsupportedAlgorithm { get; } = new(
        "unsupported_algorithm",
        "The attestation statement's algorithm identifier is not one this verification procedure supports.");

    /// <summary>
    /// A TPM attestation's <c>certInfo</c> (TPMS_ATTEST) does not carry the <c>TPM_GENERATED_VALUE</c>
    /// magic value.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">W3C Web Authentication Level 3, section 8.3: TPM Attestation Statement Format.</see>
    /// "Verify that magic is set to TPM_GENERATED_VALUE."
    /// </remarks>
    public static Fido2AttestationError CertInfoNotTpmGenerated { get; } = new(
        "cert_info_not_tpm_generated",
        "The tpm attestation's certInfo does not carry the TPM_GENERATED_VALUE magic value.");

    /// <summary>
    /// A TPM attestation's <c>certInfo</c> (TPMS_ATTEST) does not carry the <c>TPM_ST_ATTEST_CERTIFY</c>
    /// type.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">W3C Web Authentication Level 3, section 8.3: TPM Attestation Statement Format.</see>
    /// "Verify that type is set to TPM_ST_ATTEST_CERTIFY."
    /// </remarks>
    public static Fido2AttestationError CertInfoNotCertifyType { get; } = new(
        "cert_info_not_certify_type",
        "The tpm attestation's certInfo is not of type TPM_ST_ATTEST_CERTIFY.");

    /// <summary>
    /// A TPM attestation's <c>certInfo.extraData</c> does not equal the digest of
    /// <c>attToBeSigned</c> computed with the hash algorithm the statement's <c>alg</c> names.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">W3C Web Authentication Level 3, section 8.3: TPM Attestation Statement Format.</see>
    /// "Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed
    /// in 'alg'."
    /// </remarks>
    public static Fido2AttestationError AttestationDigestMismatch { get; } = new(
        "attestation_digest_mismatch",
        "The tpm attestation's certInfo.extraData does not equal the digest of attToBeSigned under the statement's alg.");

    /// <summary>
    /// A TPM attestation's <c>certInfo.attested</c> (TPMS_CERTIFY_INFO) <c>name</c> field is not a
    /// valid Name for <c>pubArea</c>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">W3C Web Authentication Level 3, section 8.3: TPM Attestation Statement Format.</see>
    /// "Verify that attested contains a TPMS_CERTIFY_INFO structure ... whose name field contains a
    /// valid Name for pubArea, as computed using the procedure specified in [TPMv2-Part1] section 16
    /// using the nameAlg in the pubArea."
    /// </remarks>
    public static Fido2AttestationError CertifiedNameMismatch { get; } = new(
        "certified_name_mismatch",
        "The tpm attestation's certInfo.attested.name is not a valid Name for pubArea.");

    /// <summary>
    /// The public key specified by a TPM attestation's <c>pubArea</c> (its <c>parameters</c> and
    /// <c>unique</c> fields) is not identical to the credential public key in the authenticator
    /// data's attested credential data.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">W3C Web Authentication Level 3, section 8.3: TPM Attestation Statement Format.</see>
    /// "Verify that the public key specified by the parameters and unique fields of pubArea is
    /// identical to the credentialPublicKey in the attestedCredentialData in authenticatorData."
    /// </remarks>
    public static Fido2AttestationError PublicAreaKeyMismatch { get; } = new(
        "public_area_key_mismatch",
        "The public key specified by pubArea's parameters and unique fields is not identical to the credentialPublicKey.");
}
