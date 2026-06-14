using System.Buffers;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Cryptography;

namespace Verifiable.Vcalm;

/// <summary>
/// The application-supplied seams the VCALM 1.0 §3.5.2 <c>POST /presentations</c> holder endpoint
/// composes over the library's tested presentation Data Integrity sign surface
/// (<see cref="PresentationDataIntegrityExtensions.SignAsync"/>, W3C VC Data Integrity §4.2 Add Proof
/// with the <c>authentication</c> proof purpose). Carried on
/// <see cref="VcalmIntegration.VcalmPresentationSigning"/>; the §3.5.2 counterpart of the §3.2.1
/// <see cref="VcalmCredentialIssuance"/>.
/// </summary>
/// <remarks>
/// <para>
/// The library never owns the holder's signing key and does not hardcode the cryptosuite /
/// canonicalization choice: the deployment supplies the holder's private key, the verification method
/// that resolves to its public counterpart, the cryptosuite, the canonicalizer, the proof-value codec,
/// the serializers, the digest function, and the memory pool. The §3.5.2 request's
/// <c>options.challenge</c> / <c>options.domain</c> / <c>options.verificationMethod</c> /
/// <c>options.created</c> bind the proof at request time; <see cref="DefaultVerificationMethodId"/> is
/// the §3.5.2 fallback ("If omitted, a default verification method will be used.").
/// </para>
/// <para>
/// When this record is unwired the §3.5.2 endpoint does not materialize (a holder presentation surface
/// that cannot sign a presentation would be a dead route). The Core
/// <see cref="PresentationDataIntegrityExtensions.SignAsync"/> requires a non-empty challenge and
/// domain — the §3.5.2 endpoint enforces their presence before composing this seam, mapping an absent
/// challenge / domain to a §3.5.2 400.
/// </para>
/// </remarks>
public sealed record VcalmPresentationSigning
{
    /// <summary>The holder private key material that produces the presentation proof's signature.</summary>
    public required PrivateKeyMemory PrivateKey { get; init; }

    /// <summary>
    /// The §3.5.2 default <c>verificationMethod</c> DID URL the proof carries when the request omits
    /// <c>options.verificationMethod</c> ("If omitted, a default verification method will be used.").
    /// Resolves to the public counterpart of <see cref="PrivateKey"/> through the holder's
    /// <c>authentication</c> relationship.
    /// </summary>
    public required string DefaultVerificationMethodId { get; init; }

    /// <summary>The cryptosuite the presentation proof is signed with (e.g. <c>EddsaJcs2022CryptosuiteInfo.Instance</c>).</summary>
    public required CryptosuiteInfo Cryptosuite { get; init; }

    /// <summary>The canonicalization function for the cryptosuite (RDFC-1.0 or JCS).</summary>
    public required CanonicalizationDelegate Canonicalize { get; init; }

    /// <summary>
    /// Resolves JSON-LD contexts for an RDFC-based cryptosuite, or <see langword="null"/> for a
    /// JCS-based cryptosuite that needs no external resolution.
    /// </summary>
    public ContextResolverDelegate? ContextResolver { get; init; }

    /// <summary>Encodes the signature bytes into the proof value string (e.g. base58btc multibase).</summary>
    public required ProofValueEncoderDelegate EncodeProofValue { get; init; }

    /// <summary>Serializes a presentation to its canonicalization input.</summary>
    public required PresentationSerializeDelegate SerializePresentation { get; init; }

    /// <summary>Deserializes a presentation JSON string back into a presentation.</summary>
    public required PresentationDeserializeDelegate DeserializePresentation { get; init; }

    /// <summary>Serializes the proof options document to its canonicalization input.</summary>
    public required ProofOptionsSerializeDelegate SerializeProofOptions { get; init; }

    /// <summary>The byte encoder (e.g. base58 encoder) the proof-value encoder composes.</summary>
    public required EncodeDelegate Encoder { get; init; }

    /// <summary>Computes the proof's message digest.</summary>
    public required ComputeDigestDelegate ComputeDigest { get; init; }

    /// <summary>The memory pool backing the transient signing buffers.</summary>
    public required MemoryPool<byte> MemoryPool { get; init; }
}
