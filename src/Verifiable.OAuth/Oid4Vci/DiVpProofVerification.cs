using System.Buffers;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// Deserializes one OID4VCI 1.0 Appendix F.2 <c>di_vp</c> array entry — a W3C Verifiable
/// Presentation JSON object carried verbatim as its serialized JSON in
/// <see cref="CredentialRequest.DiVpProofs"/> — into the embedded-secured presentation model the
/// library's Data Integrity verifier consumes.
/// </summary>
/// <remarks>
/// The deserialization is a JSON concern, so it lives behind a delegate the application supplies
/// (the default implementation is in <c>Verifiable.Json</c>): the <c>Verifiable.OAuth</c>
/// serialization firewall keeps <c>System.Text.Json</c> out of the library, exactly as
/// <see cref="Server.ParseCredentialRequestDelegate"/> does for the request body. Returning
/// <see langword="null"/> means the entry was not a parseable secured presentation; the proof is
/// rejected as <c>invalid_proof</c>.
/// </remarks>
/// <param name="presentationJson">The serialized JSON of one <c>di_vp</c> array entry.</param>
/// <returns>The parsed secured presentation, or <see langword="null"/> when it does not parse.</returns>
public delegate DataIntegritySecuredPresentation? DeserializeDiVpPresentationDelegate(string presentationJson);


/// <summary>
/// The application-supplied seams that OPT IN to library-side verification of OID4VCI 1.0
/// Appendix F.2 <c>di_vp</c> key proofs at the §8 Credential Endpoint. Carried on
/// <see cref="CredentialProofExpectation.DiVpVerification"/>; when it is <see langword="null"/> the
/// endpoint leaves each <c>di_vp</c> presentation in <see cref="CredentialRequest.DiVpProofs"/> for
/// the issuance seam to verify (the established parse-and-surface default), exactly as the
/// expectation seam itself is opt-in for the <c>jwt</c> path.
/// </summary>
/// <remarks>
/// <para>
/// The library does not re-roll Data Integrity verification: <see cref="CredentialProofValidator"/>
/// composes the same tested <see cref="PresentationDataIntegrityExtensions.VerifyAsync"/> surface
/// the W3C presentation-verification flow uses, mapping <see cref="VerifierChallenge"/> to the
/// expected <c>c_nonce</c> and <see cref="VerifierDomain"/> to the Credential Issuer Identifier per
/// Appendix F.2.
/// </para>
/// <para>
/// The holder is resolved through the library's <see cref="DidResolver"/> seam rather than a
/// bespoke delegate: the credential endpoint's <see cref="Verifiable.Core.ExchangeContext"/> threads
/// into <see cref="DidResolver.ResolveAsync"/>, so a remote <c>did:web</c> holder is fetched under
/// the context's SSRF <c>OutboundFetchPolicy</c>, while a <c>did:key</c> holder derives locally —
/// the same resolver the OAuth <c>decentralized_identifier:</c> path uses.
/// </para>
/// <para>
/// The cryptographic delegates here are the SAME shapes
/// <see cref="PresentationDataIntegrityExtensions.VerifyAsync"/> takes — the canonicalizer for the
/// cryptosuite, the proof-value decoder and its byte decoder, the presentation / proof-options
/// serializers, and the digest function. The application sources them from the same library
/// primitives the signing side uses (JCS canonicalization, base58btc multibase, the digest
/// provider). <see cref="MemoryPool"/> backs the transient verify buffers.
/// </para>
/// </remarks>
public sealed record DiVpProofVerification
{
    /// <summary>Parses one <c>di_vp</c> array entry into the secured presentation model.</summary>
    public required DeserializeDiVpPresentationDelegate Deserialize { get; init; }

    /// <summary>
    /// The library's DID-resolution seam, configured with the method handlers the deployment
    /// supports. The validator resolves the holder DID (the presentation's <c>holder</c>, falling
    /// back to the proof <c>verificationMethod</c>'s base DID) through it, threading the credential
    /// endpoint's <see cref="Verifiable.Core.ExchangeContext"/> so a remote <c>did:web</c> holder
    /// resolves under the context's <c>OutboundFetch</c> SSRF policy. The proof is verified against
    /// the resolved document's <c>authentication</c> verification relationship (Appendix F.2: "The
    /// Credential Issuer MUST validate that the W3C Verifiable Presentation used as a proof is
    /// actually signed with a key in the possession of the Holder").
    /// </summary>
    public required DidResolver Resolver { get; init; }

    /// <summary>The canonicalization function for the presentation proof's cryptosuite (e.g. JCS).</summary>
    public required CanonicalizationDelegate Canonicalize { get; init; }

    /// <summary>
    /// Resolves JSON-LD contexts for RDFC-based cryptosuites, or <see langword="null"/> for
    /// JCS-based cryptosuites that need no external resolution.
    /// </summary>
    public ContextResolverDelegate? ContextResolver { get; init; }

    /// <summary>Decodes a proof value string (e.g. base58btc multibase) into the signature bytes.</summary>
    public required ProofValueDecoderDelegate DecodeProofValue { get; init; }

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
}
