using System.Buffers;
using System.Collections.Immutable;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Cryptography;

namespace Verifiable.Vcalm;

/// <summary>
/// The application-supplied seams the VCALM 1.0 §3.2.1 <c>POST /credentials/issue</c> issuer composes
/// over the library's tested Data Integrity sign surface
/// (<see cref="CredentialDataIntegrityExtensions.SignAsync"/>, W3C VC Data Integrity §4.2 Add Proof).
/// Carried on <see cref="VcalmIntegration.VcalmCredentialIssuance"/>; the issuer counterpart of
/// <see cref="VcalmCredentialVerification"/>.
/// </summary>
/// <remarks>
/// <para>
/// The library does not re-roll Data Integrity signing and does not hardcode the cryptosuite /
/// canonicalization choice: the deployment supplies the signing key, the cryptosuite, the
/// canonicalizer, the proof-value codec, the serializers, and the digest function on each
/// <see cref="VcalmProofDescriptor"/>, and the issuer maps the §3.2.1 outcome onto a 201 response.
/// When this whole record is unwired the §3.2.1 endpoint cannot materialize (an issuer that cannot
/// secure a credential would be a dead route).
/// </para>
/// <para>
/// <see cref="ConfiguredIssuer"/> is the §3.2.1 instance-identity check ("The provided value of
/// 'issuer' does not match the expected configuration." → 400). <see cref="SigningDescriptors"/>
/// carries one-or-more proof descriptors so the §3.2.1 multi-proof MUST ("if multiple proofs are
/// needed, the instance MUST attach all of these proofs in response to a single call") is satisfied
/// in a single issue call. <see cref="ExistingProofHandling"/> governs the §3.2.1 caller-supplied
/// existing-proof case (Proof Sets / Proof Chains / Error).
/// </para>
/// </remarks>
public sealed record VcalmCredentialIssuance
{
    /// <summary>
    /// The issuer identity this instance secures credentials as. §3.2.1: a request whose
    /// <c>credential.issuer</c> (the <c>id</c>, whether the issuer was given as a string or an
    /// object) does not equal this value is a 400 ("The provided value of 'issuer' does not match
    /// the expected configuration.").
    /// </summary>
    public required string ConfiguredIssuer { get; init; }

    /// <summary>
    /// The one-or-more proof descriptors the instance attaches in a single §3.2.1 issue call. A
    /// single descriptor is an ordinary single-proof issuance; two or more realize the §3.2.1
    /// multi-proof MUST (all proofs attached in one call), appended in list order as a §2.1.2 proof
    /// chain (each subsequent descriptor's proof chains onto the prior via <c>previousProof</c>).
    /// </summary>
    public required ImmutableArray<VcalmProofDescriptor> SigningDescriptors { get; init; }

    /// <summary>
    /// How a caller-supplied credential that already carries proofs is handled (§3.2.1 Proof Sets /
    /// Proof Chains / Error). Defaults to <see cref="VcalmExistingProofHandling.Error"/> — an
    /// instance rejects pre-proofed input unless it opted into appending over it.
    /// </summary>
    public VcalmExistingProofHandling ExistingProofHandling { get; init; } = VcalmExistingProofHandling.Error;

    /// <summary>
    /// Whether this instance supports the §3.2.1 <c>options.mandatoryPointers</c> option. §2.4: "any
    /// given instance configuration MAY prohibit client use of some options properties." When
    /// <see langword="false"/>, an issue call carrying <c>mandatoryPointers</c> is the §2.4
    /// unknown/inapplicable-option case → 400 with the §3.8
    /// <see cref="VcalmProblemTypes.UnknownOptionProvided"/> type, because the configured
    /// (non-selective-disclosure) cryptosuites cannot apply it.
    /// </summary>
    public bool SupportsMandatoryPointers { get; init; }

    /// <summary>The memory pool backing the transient signing buffers.</summary>
    public required MemoryPool<byte> MemoryPool { get; init; }
}


/// <summary>
/// One Data Integrity proof descriptor an §3.2.1 issuer instance attaches: the signing key, the
/// verification method that resolves to its public counterpart, the cryptosuite, and the
/// cryptosuite-matching canonicalizer / codec / serializer seams the library's
/// <see cref="CredentialDataIntegrityExtensions.SignAsync"/> composes. Mirrors
/// <see cref="DataIntegritySigningConfig"/> field-for-field, minus the per-build members the issue
/// request supplies.
/// </summary>
public sealed record VcalmProofDescriptor
{
    /// <summary>The private key material that produces this proof's signature.</summary>
    public required PrivateKeyMemory PrivateKey { get; init; }

    /// <summary>
    /// The DID URL identifying the verification method that resolves to the public counterpart of
    /// <see cref="PrivateKey"/> (e.g. <c>did:web:issuer.example#key-1</c>).
    /// </summary>
    public required string VerificationMethodId { get; init; }

    /// <summary>The cryptosuite this descriptor signs with (e.g. <c>EddsaRdfc2022CryptosuiteInfo.Instance</c>).</summary>
    public required CryptosuiteInfo Cryptosuite { get; init; }

    /// <summary>The canonicalization function for the descriptor's cryptosuite (RDFC-1.0 or JCS).</summary>
    public required CanonicalizationDelegate Canonicalize { get; init; }

    /// <summary>
    /// Resolves JSON-LD contexts for an RDFC-based cryptosuite, or <see langword="null"/> for a
    /// JCS-based cryptosuite that needs no external resolution.
    /// </summary>
    public ContextResolverDelegate? ContextResolver { get; init; }

    /// <summary>Encodes the signature bytes into the proof value string (e.g. base58btc multibase).</summary>
    public required ProofValueEncoderDelegate EncodeProofValue { get; init; }

    /// <summary>Serializes a credential to its canonicalization input.</summary>
    public required CredentialSerializeDelegate SerializeCredential { get; init; }

    /// <summary>Deserializes a credential JSON string back into a credential.</summary>
    public required CredentialDeserializeDelegate DeserializeCredential { get; init; }

    /// <summary>Serializes the proof options document to its canonicalization input.</summary>
    public required ProofOptionsSerializeDelegate SerializeProofOptions { get; init; }

    /// <summary>The byte encoder (e.g. base58 encoder) the proof-value encoder composes.</summary>
    public required EncodeDelegate Encoder { get; init; }

    /// <summary>Computes the proof's message digest.</summary>
    public required ComputeDigestDelegate ComputeDigest { get; init; }
}
