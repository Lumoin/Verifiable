using System.Buffers;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Cryptography;

namespace Verifiable.Vcalm;

/// <summary>
/// The application-supplied seams the VCALM 1.0 §3.5.1 <c>POST /credentials/derive</c> holder endpoint
/// composes over the library's tested ecdsa-sd-2023 selective-disclosure derive surface
/// (<see cref="CredentialEcdsaSd2023Extensions.DeriveProofAsync"/>, W3C VC-DI-ECDSA §3.5
/// createDisclosureData). Carried on <see cref="VcalmIntegration.VcalmCredentialDerivation"/>; the
/// holder counterpart of <see cref="VcalmCredentialIssuance"/> / <see cref="VcalmCredentialVerification"/>.
/// </summary>
/// <remarks>
/// <para>
/// §3.5.1 derives a selectively-disclosed credential from a base-proofed ecdsa-sd-2023 credential: the
/// request's <c>options.selectivePointers</c> become the JSON pointers to disclose, which the library
/// maps to its <see cref="Verifiable.Core.Model.SelectiveDisclosure.CredentialPath"/> request set and
/// runs through <c>DeriveProofAsync</c> to produce a derived credential carrying only the disclosed
/// claims (plus the issuer's mandatory pointers, which are always revealed). The library does not
/// re-roll the selective-disclosure cryptography: the deployment supplies the canonicalizer, the
/// statement partitioner, the JSON-LD fragment selector, the base / derived proof codecs, the
/// serializers, the base64url codec, and the memory pool.
/// </para>
/// <para>
/// A distinct seam record (rather than reusing <see cref="VcalmCredentialVerification"/> /
/// <see cref="VcalmCredentialIssuance"/>) is justified because the §3.5.1 derive path needs members
/// neither of those carries: <see cref="PartitionStatements"/>, <see cref="SelectFragments"/>,
/// <see cref="ParseBaseProof"/>, and <see cref="SerializeDerivedProof"/> are ecdsa-sd-2023-specific,
/// and derive needs BOTH the encoder and the decoder. When this record is unwired the §3.5.1 endpoint
/// does not materialize (a holder presentation surface that cannot derive would be a dead route).
/// </para>
/// </remarks>
public sealed record VcalmCredentialDerivation
{
    /// <summary>The canonicalization function for the ecdsa-sd-2023 cryptosuite (RDFC-1.0).</summary>
    public required CanonicalizationDelegate Canonicalize { get; init; }

    /// <summary>Resolves the JSON-LD contexts the RDFC-based ecdsa-sd-2023 derive canonicalizes against.</summary>
    public required ContextResolverDelegate ContextResolver { get; init; }

    /// <summary>Partitions canonical N-Quad statements into the mandatory and non-mandatory sets.</summary>
    public required PartitionStatementsDelegate PartitionStatements { get; init; }

    /// <summary>Selects the JSON-LD fragments (by RFC 6901 pointer) that form the reduced derived credential.</summary>
    public required SelectJsonLdFragmentsDelegate SelectFragments { get; init; }

    /// <summary>Parses the issuer's ecdsa-sd-2023 base proof value into its components.</summary>
    public required ParseBaseProofDelegate ParseBaseProof { get; init; }

    /// <summary>Serializes the derived proof value the holder attaches to the reduced credential.</summary>
    public required SerializeDerivedProofDelegate SerializeDerivedProof { get; init; }

    /// <summary>Serializes a credential to its canonicalization input.</summary>
    public required CredentialSerializeDelegate SerializeCredential { get; init; }

    /// <summary>Deserializes a credential JSON string back into a credential.</summary>
    public required CredentialDeserializeDelegate DeserializeCredential { get; init; }

    /// <summary>The base64url byte encoder the derive proof-value serializer composes.</summary>
    public required EncodeDelegate Encoder { get; init; }

    /// <summary>The base64url byte decoder the base-proof parser composes.</summary>
    public required DecodeDelegate Decoder { get; init; }

    /// <summary>The memory pool backing the transient derive buffers.</summary>
    public required MemoryPool<byte> MemoryPool { get; init; }
}
