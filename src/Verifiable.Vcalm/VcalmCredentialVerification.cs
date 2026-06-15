using System.Buffers;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;

namespace Verifiable.Vcalm;

/// <summary>
/// The application-supplied seams that the VCALM 1.0 §3.3.1 / §3.3.2 verifier composes over the
/// library's tested Data Integrity verify surface
/// (<see cref="CredentialDataIntegrityExtensions.VerifyAsync"/> and
/// <see cref="PresentationDataIntegrityExtensions.VerifyAsync"/>, W3C VC Data Integrity §4.3 Verify
/// Proof). Carried on <see cref="VcalmIntegration.VcalmCredentialVerification"/> so the deployment
/// wires the cryptographic primitives the verifier surface uses.
/// </summary>
/// <remarks>
/// <para>
/// The library does not re-roll Data Integrity verification and does not hardcode the
/// cryptosuite / canonicalization choice (RDFC-1.0 for eddsa-rdfc-2022 / ecdsa-sd-2023, JCS for
/// eddsa-jcs-2022): the deployment supplies the canonicalizer, the proof-value codec, the
/// serializers, and the digest function, and the verifier maps the §4.3 verdict onto the §3.8.1
/// error/warning model. When this whole record is unwired, the verifier reports each embedded-proof
/// step as unverifiable (fail-closed) rather than asserting a pass.
/// </para>
/// <para>
/// The issuer / holder DID is resolved through the library's <see cref="DidResolver"/> seam,
/// threading the verify request's <see cref="Verifiable.Core.ExchangeContext"/> so a remote
/// <c>did:web</c> controller is fetched under the context's SSRF <c>OutboundFetch</c> policy, while a
/// <c>did:key</c> controller derives locally — the same resolver the OID4VP / di_vp paths use.
/// </para>
/// </remarks>
public sealed record VcalmCredentialVerification
{
    /// <summary>
    /// The library's DID-resolution seam, configured with the method handlers the deployment
    /// supports. The verifier resolves the issuer DID of a credential proof's <c>verificationMethod</c>
    /// (and the holder DID of a presentation proof) through it, threading the verify request's
    /// <see cref="Verifiable.Core.ExchangeContext"/> for the SSRF policy.
    /// </summary>
    public required DidResolver Resolver { get; init; }

    /// <summary>The canonicalization function for the proof's cryptosuite (RDFC-1.0 or JCS).</summary>
    public required CanonicalizationDelegate Canonicalize { get; init; }

    /// <summary>
    /// Resolves JSON-LD contexts for RDFC-based cryptosuites, or <see langword="null"/> for
    /// JCS-based cryptosuites that need no external resolution.
    /// </summary>
    public ContextResolverDelegate? ContextResolver { get; init; }

    /// <summary>Decodes a proof value string (e.g. base58btc multibase) into the signature bytes.</summary>
    public required ProofValueDecoderDelegate DecodeProofValue { get; init; }

    /// <summary>Serializes a credential to its canonicalization input.</summary>
    public required CredentialSerializeDelegate SerializeCredential { get; init; }

    /// <summary>Serializes a presentation to its canonicalization input.</summary>
    public required PresentationSerializeDelegate SerializePresentation { get; init; }

    /// <summary>Serializes the proof options document to its canonicalization input.</summary>
    public required ProofOptionsSerializeDelegate SerializeProofOptions { get; init; }

    /// <summary>The byte decoder (e.g. base58 decoder) the proof-value decoder composes.</summary>
    public required DecodeDelegate Decoder { get; init; }

    /// <summary>Computes the proof's message digest.</summary>
    public required ComputeDigestDelegate ComputeDigest { get; init; }

    /// <summary>The memory pool backing the transient verify buffers.</summary>
    public required MemoryPool<byte> MemoryPool { get; init; }

    /// <summary>
    /// Parses an ecdsa-sd-2023 DERIVED proof value (a <c>u</c>-prefixed base64url multibase wrapping a
    /// CBOR <c>0xd9 0x5d 0x01</c>-tagged <c>[baseSignature, ephemeralPublicKey, signatures, labelMap,
    /// mandatoryIndexes]</c>) into its components — the parser
    /// <see cref="CredentialEcdsaSd2023Extensions.VerifyDerivedProofAsync"/> consumes
    /// (W3C VC-DI-ECDSA §3.4.7 <c>parseDerivedProofValue</c>). When unset, an ecdsa-sd-2023 derived
    /// credential cannot be selectively-disclosure-verified and falls through to the generic Data
    /// Integrity path (which reports it unverifiable) — non-SD deployments are unaffected.
    /// </summary>
    public ParseDerivedProofDelegate? ParseDerivedProof { get; init; }

    /// <summary>
    /// The ECDSA verification function the ecdsa-sd-2023 derived-proof verifier
    /// (<see cref="CredentialEcdsaSd2023Extensions.VerifyDerivedProofAsync"/>) calls to check the
    /// issuer's base signature and each disclosed-statement signature (W3C VC-DI-ECDSA §3.4.8
    /// <c>verifyDerivedProof</c>). Required alongside <see cref="ParseDerivedProof"/> for SD
    /// verification; <see langword="null"/> on a non-SD deployment.
    /// </summary>
    public VerificationDelegate? VerifyDerivedSignature { get; init; }

    /// <summary>
    /// The base64url byte encoder the ecdsa-sd-2023 derived-proof parser composes to reconstruct the
    /// label map's string values from the CBOR-stored raw bytes (W3C VC-DI-ECDSA §3.4.7). Required
    /// alongside <see cref="ParseDerivedProof"/> for SD verification; <see langword="null"/> on a
    /// non-SD deployment.
    /// </summary>
    public EncodeDelegate? SdProofEncoder { get; init; }

    /// <summary>
    /// The base64url byte decoder the ecdsa-sd-2023 derived-proof parser composes to decode the
    /// <c>u</c>-prefixed multibase proof value into its CBOR bytes (W3C VC-DI-ECDSA §3.4.7). This is a
    /// base64url decoder, distinct from <see cref="Decoder"/> (the base58 decoder the base/simple
    /// proof-value codec composes). Required alongside <see cref="ParseDerivedProof"/> for SD
    /// verification; <see langword="null"/> on a non-SD deployment.
    /// </summary>
    public DecodeDelegate? SdProofDecoder { get; init; }
}
