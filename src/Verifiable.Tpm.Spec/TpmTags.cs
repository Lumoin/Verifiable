using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Tpm.Spec;

/// <summary>
/// Pre-built <see cref="Tag"/> instances for common TPM data types.
/// </summary>
/// <remarks>
/// <para>
/// This static class provides ready-to-use tags for TPM buffer types.
/// Each tag contains the appropriate <see cref="Purpose"/> and
/// <see cref="MaterialSemantics"/> metadata.
/// </para>
/// <para>
/// <strong>Usage</strong>
/// </para>
/// <code>
/// //Use a pre-built tag when creating TPM buffers.
/// var nonce = new Tpm2bNonce(storage, TpmTags.Nonce);
///
/// //Or retrieve components from a tag.
/// var purpose = TpmTags.Auth.Get&lt;Purpose&gt;();
/// </code>
/// </remarks>
/// <seealso cref="Tag"/>
/// <seealso cref="Purpose"/>
/// <seealso cref="MaterialSemantics"/>
public static class TpmTags
{
    /// <summary>
    /// Tag for TPM2B_NONCE - session nonce values.
    /// </summary>
    /// <remarks>
    /// Used for nonceCaller and nonceTPM in session protocols.
    /// See TPM 2.0 Library Part 1, clause 16.6.3 - Session Nonces.
    /// </remarks>
    public static Tag Nonce { get; } = Tag.Create(Purpose.Nonce).With(MaterialSemantics.Direct);

    /// <summary>
    /// Tag for TPM2B_AUTH - authorization values.
    /// </summary>
    /// <remarks>
    /// Used for passwords, HMACs, and authValue in authorization protocols.
    /// See TPM 2.0 Library Part 1, clause 16.6.4 - Authorization Values.
    /// </remarks>
    public static Tag Auth { get; } = Tag.Create(Purpose.Hmac).With(MaterialSemantics.Direct);

    /// <summary>
    /// Tag for TPM2B_DIGEST - hash digest values.
    /// </summary>
    /// <remarks>
    /// Used for hash results, PCR values, and cpHash/rpHash computations.
    /// </remarks>
    public static Tag Digest { get; } = Tag.Create(Purpose.Digest).With(MaterialSemantics.Direct);

    /// <summary>
    /// Tag for raw TPM response data.
    /// </summary>
    /// <remarks>
    /// Used for the raw byte response from a TPM command before parsing.
    /// </remarks>
    public static Tag Response { get; } = Tag.Create(Purpose.Transport).With(MaterialSemantics.Direct);

    /// <summary>
    /// Tag for TPM2B_ECC_PARAMETER - ECC coordinate values.
    /// </summary>
    /// <remarks>
    /// Used for x and y coordinates in ECC public points.
    /// See TPM 2.0 Library Part 2, clause 11.2.5.1.
    /// </remarks>
    public static Tag EccParameter { get; } = Tag.Create(Purpose.Verification).With(MaterialSemantics.Direct);

    /// <summary>
    /// Tag for TPM2B_SENSITIVE_DATA - sensitive user data.
    /// </summary>
    /// <remarks>
    /// Used for sensitive data in sealed objects or key derivation.
    /// See TPM 2.0 Library Part 2, clause 11.1.14, Table 170 (Definition of TPM2B_SENSITIVE_DATA Structure).
    /// </remarks>
    public static Tag SensitiveData { get; } = Tag.Create(Purpose.Encryption).With(MaterialSemantics.Direct);

    /// <summary>
    /// Tag for TPM2B_PRIVATE_KEY_RSA - a prime factor of an RSA private key.
    /// </summary>
    /// <remarks>
    /// Used for the <c>rsa</c> arm of <c>TPMU_SENSITIVE_COMPOSITE</c> (TPM 2.0 Library Part 2, clause 12.3.2.3,
    /// Table 239): the private prime, not a full private-key encoding, so <see cref="Purpose.Signing"/> marks it
    /// as private material without claiming a particular exponent/CRT layout.
    /// See TPM 2.0 Library Part 2, clause 11.2.4.8, Table 196.
    /// </remarks>
    public static Tag PrivateKeyFactor { get; } = Tag.Create(Purpose.Signing).With(MaterialSemantics.Direct);

    /// <summary>
    /// Tag for a session key: the KDFa-derived HMAC and parameter-encryption key a bound and/or
    /// salted session carries for its whole life.
    /// </summary>
    /// <remarks>
    /// See TPM 2.0 Library Part 1, clause 16.6.10 equation 20 - Bound Session Key Generation. Distinct from
    /// <see cref="Auth"/> (a caller-supplied authorization value) even though both are HMAC-purposed:
    /// a session key is KDFa output the TPM itself derives and retains.
    /// </remarks>
    public static Tag SessionKey { get; } = Tag.Create(Purpose.Hmac).With(MaterialSemantics.Direct);

    /// <summary>
    /// Tag for a session's bound-entity value: the bind entity's Name with its authValue XORed into
    /// the tail, recorded once at <c>TPM2_StartAuthSession()</c> and compared at every bind-omission
    /// decision.
    /// </summary>
    /// <remarks>
    /// See TPM 2.0 Library Part 1, clause 16.6.10 ("the authorization value is combined with the Name and
    /// stored in the SESSION boundEntity member") and Part 4, <c>SessionComputeBoundEntity()</c>.
    /// </remarks>
    public static Tag BoundEntity { get; } = Tag.Create(Purpose.Verification).With(MaterialSemantics.Direct);

    /// <summary>
    /// Tag for a hierarchy proof seed: the rotatable secret the storage and endorsement hierarchy
    /// proofs (<c>shProof</c>, <c>ehProof</c>) derive from, standing in for the Storage Primary Seed
    /// a real TPM keeps in NV.
    /// </summary>
    /// <remarks>
    /// See TPM 2.0 Library Part 1, clauses 11.4.4 and 11.5. HMAC-purposed because every consumer keys a
    /// proof HMAC from it (tickets, context integrity); distinct from <see cref="SessionKey"/> (a
    /// per-session KDFa output) and from <see cref="Auth"/> (a caller-supplied authorization value) —
    /// this seed is TPM-internal root material that never crosses the wire.
    /// </remarks>
    public static Tag StorageProofSeed { get; } = Tag.Create(Purpose.Hmac).With(MaterialSemantics.Direct);

    /// <summary>
    /// Tag for TPM2B_SHARED_SECRET - the shared secret a KEM key exchange produces.
    /// </summary>
    /// <remarks>
    /// Used for the <c>sharedSecret</c> response of <c>TPM2_Encapsulate()</c> and
    /// <c>TPM2_Decapsulate()</c> (TPM 2.0 Library Part 2, clause 10.3.12, Table 100). Carries
    /// <see cref="Purpose.Exchange"/> — key-agreement output, the same purpose the ECC and X25519
    /// exchange-key tags in <c>CryptoTags</c> carry — rather than <see cref="Digest"/>, because a KEM
    /// shared secret is DHKEM/ML-KEM derived material feeding a further KDF, not a hash result.
    /// </remarks>
    public static Tag SharedSecret { get; } = Tag.Create(Purpose.Exchange).With(MaterialSemantics.Direct);
}
